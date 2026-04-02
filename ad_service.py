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


def test_connection(settings):
    """
    Test connection to AD server.
    Returns (success: bool, message: str)
    """
    ldap3 = _get_ldap3()
    if not ldap3:
        return False, 'Библиотека ldap3 не установлена. Выполните: pip install ldap3'

    if not settings or not settings.server:
        return False, 'Настройки AD не заполнены'

    try:
        server = ldap3.Server(settings.server, get_info=ldap3.ALL, connect_timeout=5)
        conn = ldap3.Connection(
            server,
            user=settings.bind_user,
            password=settings.bind_password,
            auto_bind=True
        )
        conn.unbind()
        return True, 'Подключение успешно!'
    except Exception as e:
        logger.error(f'AD connection test failed: {e}')
        return False, f'Ошибка подключения: {str(e)}'


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
        server = ldap3.Server(settings.server, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(
            server,
            user=settings.bind_user,
            password=settings.bind_password,
            auto_bind=True
        )

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

                # Check if user is disabled (UAC flag 2)
                uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
                is_active = not bool(uac & 2)

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
                        is_active=is_active
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
        server = ldap3.Server(settings.server, connect_timeout=5)

        # Try to find user's DN first via bind user
        bind_conn = ldap3.Connection(
            server,
            user=settings.bind_user,
            password=settings.bind_password,
            auto_bind=True
        )

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
