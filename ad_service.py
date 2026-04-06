"""
Active Directory integration service using ldap3.
Provides user synchronization and LDAP authentication.
"""
import logging
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)


def _get_ldap3():
    """Lazy-load ldap3 to avoid import error if not installed."""
    try:
        import ldap3
        return ldap3
    except ImportError:
        return None


def _get_connection(settings):
    """Create and return an LDAP connection with StartTLS support."""
    ldap3 = _get_ldap3()
    if not ldap3:
        return None, "Библиотека ldap3 не установлена"
    
    try:
        # Check if the server is specified with ldaps://
        is_ldaps = settings.server.startswith('ldaps://') if settings.server else False
        
        server = ldap3.Server(settings.server, get_info=ldap3.ALL, connect_timeout=10, use_ssl=is_ldaps)
        conn = ldap3.Connection(
            server,
            user=settings.bind_user,
            password=settings.bind_password
        )
        
        if not conn.bind():
            return None, f"Ошибка авторизации: {conn.result['description']}"
            
        # If not LDAPS, try to upgrade to StartTLS for secure password operations
        if not is_ldaps:
            try:
                conn.start_tls()
            except Exception as tls_err:
                logger.warning(f"StartTLS failed (this might prevent password changes): {tls_err}")
                
        return conn, None
    except Exception as e:
        return None, str(e)


def test_connection(settings):
    """Test connection to AD server."""
    conn, error = _get_connection(settings)
    if error:
        return False, f"Ошибка подключения: {error}"
    conn.unbind()
    return True, "Подключение успешно!"


def sync_users(settings, db, User):
    """
    Synchronize users from Active Directory.
    Returns (created: int, updated: int, deactivated: int, errors: list)
    """
    ldap3 = _get_ldap3()
    if not ldap3:
        return 0, 0, 0, ['Библиотека ldap3 не установлена']

    if not settings or not settings.server:
        return 0, 0, 0, ['Настройки AD не заполнены']

    created = 0
    updated = 0
    deactivated = 0
    errors = []
    ad_usernames = set()

    try:
        conn, error = _get_connection(settings)
        if error:
            return 0, 0, 0, [error]


        search_filter = settings.search_filter or '(&(objectClass=user)(objectCategory=person))'

        conn.search(
            search_base=settings.base_dn,
            search_filter=search_filter,
            attributes=[
                'sAMAccountName',
                'displayName',
                'givenName',
                'sn',
                'department',
                'telephoneNumber',
                'mail',
                'userWorkstations',
                'dNSHostName',
                'userAccountControl',
            ]
        )

        for entry in conn.entries:
            try:
                sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
                if not sam or sam.lower() in ('administrator', 'admin', 'администратор', 'guest', 'krbtgt'):
                    continue

                ad_usernames.add(sam.lower())

                # Build display name
                display_name = None
                if entry.displayName:
                    display_name = str(entry.displayName)
                elif entry.givenName and entry.sn:
                    display_name = f'{entry.sn} {entry.givenName}'

                department = str(entry.department) if entry.department else None
                phone = str(entry.telephoneNumber) if entry.telephoneNumber else None
                email = str(entry.mail) if entry.mail else None

                # Check if user is disabled (UAC bit 2) and if password never expires (UAC bit 0x10000)
                uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
                is_active = not bool(uac & 2)
                pwd_never_expires = bool(uac & 0x10000)

                existing = User.query.filter(
                    db.func.lower(User.username) == sam.lower()
                ).first()

                if existing:
                    existing.full_name = display_name or existing.full_name
                    existing.department = department or existing.department
                    existing.phone = phone or existing.phone
                    existing.email = email or existing.email
                    existing.is_from_ad = True
                    existing.is_active = is_active
                    existing.password_never_expires = pwd_never_expires
                    updated += 1
                else:
                    new_user = User(
                        username=sam,
                        password=generate_password_hash('ad_user_no_local_login'),
                        full_name=display_name,
                        role='employee',
                        department=department,
                        phone=phone,
                        email=email,
                        is_from_ad=True,
                        is_active=is_active,
                        password_never_expires = pwd_never_expires
                    )
                    db.session.add(new_user)
                    created += 1

            except Exception as e:
                db.session.rollback() # VERY IMPORTANT: Clear the failed state
                errors.append(f'⚠️ Ошибка обработки пользователя {sam if "sam" in locals() else "???"}: {e}')
                logger.error(f'Error processing AD entry: {e}')

        # Deactivate local AD users not found in AD anymore
        if ad_usernames:
            ad_users_in_db = User.query.filter_by(is_from_ad=True).all()
            for u in ad_users_in_db:
                if u.username.lower() not in ad_usernames and u.is_active:
                    u.is_active = False
                    deactivated += 1

        db.session.commit()
        conn.unbind()

    except Exception as e:
        logger.error(f'AD sync failed: {e}')
        errors.append(f'Ошибка синхронизации: {str(e)}')

    return created, updated, deactivated, errors


def authenticate_ad(username, password, settings):
    """
    Authenticate a user against Active Directory.
    Returns True if authentication succeeds, False otherwise.
    """
    ldap3 = _get_ldap3()
    if not ldap3:
        return False

    if not settings or not settings.server or not settings.is_active:
        return False

    try:
        bind_conn, error = _get_connection(settings)
        if error:
            return False


        bind_conn.search(
            search_base=settings.base_dn,
            search_filter=f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))',
            attributes=['distinguishedName']
        )

        if not bind_conn.entries:
            bind_conn.unbind()
            return False

        user_dn = str(bind_conn.entries[0].distinguishedName)
        bind_conn.unbind()

        # Now authenticate with user's own credentials
        auth_conn = ldap3.Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True
        )
        auth_conn.unbind()
        return True

    except Exception as e:
        logger.debug(f'AD authentication failed for {username}: {e}')
        return False


def change_ad_password(username, new_password, settings):
    """
    Change user password in Active Directory.
    Returns (success: bool, message: str)
    """
    ldap3 = _get_ldap3()
    if not ldap3:
        return False, 'Библиотека ldap3 не установлена'

    if not settings or not settings.server:
        return False, 'Настройки AD не заполнены'

    try:
        conn, error = _get_connection(settings)
        if error:
            return False, error


        # Find user DN
        conn.search(
            search_base=settings.base_dn,
            search_filter=f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))',
            attributes=['distinguishedName']
        )

        if not conn.entries:
            conn.unbind()
            return False, f'Пользователь {username} не найден в AD'

        user_dn = str(conn.entries[0].distinguishedName)

        # Change password using ldap3 extend
        result = conn.extend.microsoft.modify_password(user_dn, new_password)
        conn.unbind()

        if result:
            return True, 'Пароль успешно изменён в Active Directory'
        else:
            return False, 'Ошибка смены пароля в AD'

    except Exception as e:
        logger.error(f'AD password change failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'


def extend_ad_password(username, settings):
    """
    Reset password clock in AD (set pwdLastSet = now) so
    password won't expire for another full policy period (~35 days).
    Returns (success: bool, message: str)
    """
    ldap3 = _get_ldap3()
    if not ldap3:
        return False, 'Библиотека ldap3 не установлена'

    if not settings or not settings.server:
        return False, 'Настройки AD не заполнены'

    try:
        conn, error = _get_connection(settings)
        if error:
            return False, error


        conn.search(
            search_base=settings.base_dn,
            search_filter=f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))',
            attributes=['distinguishedName']
        )

        if not conn.entries:
            conn.unbind()
            return False, f'Пользователь {username} не найден в AD'

        user_dn = str(conn.entries[0].distinguishedName)

        # Step 1: Set pwdLastSet = 0 (forces must-change), then = -1 (resets to now)
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]})
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])]})
        conn.unbind()

        return True, 'Срок действия пароля продлён сегодняшней датой'

    except Exception as e:
        logger.error(f'AD password extension failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'

