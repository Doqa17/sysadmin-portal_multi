import logging
import datetime
from .core import _get_ldap3, _get_connection, _parse_ad_date
from . import powershell

logger = logging.getLogger(__name__)

def _get_mode(settings):
    return getattr(settings, 'ad_modify_mode', 'auto').lower()

def sync_users(settings, db, User):
    """Synchronize users from AD to the local database."""
    conn, error = _get_connection(settings)
    if error:
        return 0, 0, 0, [error]
    
    created, updated, deactivated = 0, 0, 0
    errors = []
    
    try:
        conn.search(
            settings.base_dn, 
            settings.search_filter or '(&(objectClass=user)(objectCategory=person)(!(sAMAccountName=HealthMailbox*)))', 
            attributes=['sAMAccountName', 'displayName', 'mail', 'department', 'telephoneNumber', 'userAccountControl']
        )
        
        ad_usernames = []
        for entry in conn.entries:
            username = str(entry.sAMAccountName).lower()
            ad_usernames.append(username)
            
            user = User.query.filter(User.username.ilike(username)).first()
            uac = int(str(entry.userAccountControl))
            is_active = not (uac & 2)
            
            if not user:
                user = User(
                    username=username,
                    full_name=str(entry.displayName) if entry.displayName else username,
                    email=str(entry.mail) if entry.mail else None,
                    department=str(entry.department) if entry.department else None,
                    phone=str(entry.telephoneNumber) if entry.telephoneNumber else None,
                    is_active=is_active,
                    is_from_ad=True,
                    role='employee'
                )
                db.session.add(user)
                created += 1
            else:
                user.full_name = str(entry.displayName) if entry.displayName else user.full_name
                user.email = str(entry.mail) if entry.mail else user.email
                user.department = str(entry.department) if entry.department else user.department
                user.phone = str(entry.telephoneNumber) if entry.telephoneNumber else user.phone
                user.is_active = is_active
                user.is_from_ad = True
                updated += 1
        
        # Деактивация пользователей, которых нет в AD (только если они были помечены как AD-пользователи)
        for user in User.query.filter_by(is_from_ad=True).all():
            if user.username.lower() not in ad_usernames and user.is_active:
                user.is_active = False
                deactivated += 1
                
        db.session.commit()
        conn.unbind()
    except Exception as e:
        errors.append(str(e))
        
    return created, updated, deactivated, errors

def toggle_ad_account(username, enable, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.set_account_status(username, enable)
        if success:
            return True, f"(PS) {message}"
        ps_error = message
        if mode == 'powershell':
            return False, f"PowerShell Error: {message}"

    ldap3 = _get_ldap3()
    if not ldap3 or not settings or not settings.server:
        return False, 'Настройки AD недоступны'
    try:
        conn, error = _get_connection(settings)
        if error:
            return False, error
        conn.search(settings.base_dn,
            f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))',
            attributes=['distinguishedName', 'userAccountControl'])
        if not conn.entries:
            conn.unbind()
            return False, f'Пользователь {username} не найден в AD'
        user_dn = str(conn.entries[0].distinguishedName)
        uac = int(str(conn.entries[0].userAccountControl)) if conn.entries[0].userAccountControl else 512
        new_uac = (uac & ~2) if enable else (uac | 2)
        conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
        conn.unbind()
        action = 'включён' if enable else 'отключён'
        res_msg = f'Аккаунт успешно {action} в AD'
        if ps_error:
            res_msg = f"{res_msg} через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD toggle account failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def get_user_ad_info(username, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings or not settings.server:
        return None, 'Настройки AD недоступны'
    try:
        conn, error = _get_connection(settings)
        if error:
            return None, error
        conn.search(settings.base_dn,
            f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))',
            attributes=['userAccountControl', 'lockoutTime', 'pwdLastSet', 'lastLogonTimestamp', 'lastLogon', 'memberOf', 'description'])
        if not conn.entries:
            conn.unbind()
            return None, f'Пользователь {username} не найден'
        entry = conn.entries[0]
        
        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
        offset = settings.timezone_offset if settings.timezone_offset is not None else 0
        tz_delta = datetime.timedelta(hours=offset)
        
        lt_dt = _parse_ad_date(getattr(entry.lockoutTime, 'value', entry.lockoutTime))
        if lt_dt and lt_dt.year > 1601:
            lt_dt += tz_delta
        is_locked = lt_dt is not None and lt_dt.year > 1601
        lockout_time = lt_dt.strftime('%d.%m.%Y %H:%M') if is_locked else None
        
        ll_ts_dt = _parse_ad_date(getattr(entry.lastLogonTimestamp, 'value', entry.lastLogonTimestamp))
        ll_real_dt = _parse_ad_date(getattr(entry.lastLogon, 'value', entry.lastLogon))
        
        ll_final_dt = None
        if ll_ts_dt and ll_real_dt:
            ll_final_dt = max(ll_ts_dt, ll_real_dt)
        elif ll_ts_dt:
            ll_final_dt = ll_ts_dt
        elif ll_real_dt:
            ll_final_dt = ll_real_dt
        
        if ll_final_dt and ll_final_dt.year > 1601:
            ll_final_dt += tz_delta
            
        last_logon = ll_final_dt.strftime('%d.%m.%Y %H:%M') if ll_final_dt and ll_final_dt.year > 1601 else None
        
        pls_dt = _parse_ad_date(getattr(entry.pwdLastSet, 'value', entry.pwdLastSet))
        pwd_last_set_str = None
        pwd_expiry_str = None
        if pls_dt and pls_dt.year > 1601:
            pls_dt += tz_delta
            pwd_last_set_str = pls_dt.strftime('%d.%m.%Y')
            pwd_expiry_str = (pls_dt + datetime.timedelta(days=35)).strftime('%d.%m.%Y')
            
        groups = []
        if entry.memberOf:
            for dn in entry.memberOf:
                cn = str(dn).split(',')[0].replace('CN=', '').replace('cn=', '')
                groups.append(cn)
        conn.unbind()
        return {'is_locked': is_locked, 'lockout_time': lockout_time, 'last_logon': last_logon,
                'pwd_last_set': pwd_last_set_str, 'pwd_expiry': pwd_expiry_str,
                'pwd_never_expires': bool(uac & 0x10000), 'is_disabled': bool(uac & 2), 
                'groups': groups, 'description': str(entry.description) if entry.description else ''}, None
    except Exception as e:
        logger.error(f'AD get user info failed for {username}: {e}')
        return None, f'Ошибка: {str(e)}'

def get_ad_containers(settings):
    ldap3 = _get_ldap3()
    if not ldap3: return []
    conn, error = _get_connection(settings)
    if error: return []
    try:
        filter_query = '(|(objectClass=organizationalUnit)(objectClass=container))'
        conn.search(settings.base_dn, filter_query, attributes=['name', 'distinguishedName'])
        results = []
        for entry in conn.entries:
            dn = str(entry.distinguishedName)
            if any(x in dn for x in ['CN=System,', 'CN=Configuration,', 'CN=LostAndFound,', 'CN=Infrastructure,', 'CN=ForeignSecurityPrincipals,']):
                continue
            name = str(getattr(entry, 'name', dn))
            results.append({'name': name, 'dn': dn})
        conn.unbind()
        return sorted(results, key=lambda x: x['name'])
    except Exception:
        return []

def create_ad_user(first_name, last_name, username, password, target_ou, groups, settings, email=None, department=None, phone=None, computer_name=None):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        # Вычисляем UPN для PowerShell
        domain_parts = [p for p in settings.base_dn.split(',') if p.lower().startswith('dc=')]
        domain_name = '.'.join([p.split('=')[1] for p in domain_parts])
        upn = f"{username}@{domain_name}"

        attrs = {}
        if email: attrs['mail'] = email
        if department: attrs['department'] = department
        if phone: attrs['telephoneNumber'] = phone
        if computer_name: attrs['physicalDeliveryOfficeName'] = computer_name
        
        success, message = powershell.create_user(username, first_name, last_name, password, target_ou, upn, attrs)
        if success:
            if groups:
                for gdn in groups:
                    powershell.add_to_group(username, gdn)
            return True, f"(PS) Создан: {username}"
        ps_error = message
        if mode == 'powershell':
            return False, f"PowerShell Error: {message}"

    ldap3 = _get_ldap3()
    if not ldap3: return False, "LDAP3 не установлен"
    conn, error = _get_connection(settings)
    if error: return False, error
    
    domain_parts = [p for p in settings.base_dn.split(',') if p.lower().startswith('dc=')]
    domain_name = '.'.join([p.split('=')[1] for p in domain_parts])
    upn = f"{username}@{domain_name}"
    full_name = f"{last_name} {first_name}".strip()
    user_dn = f"CN={ldap3.utils.conv.escape_filter_chars(full_name)},{target_ou}"
    
    attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': username,
        'userPrincipalName': upn,
        'givenName': first_name,
        'sn': last_name,
        'displayName': full_name,
        'userAccountControl': 514,
    }
    if email: attributes['mail'] = email
    if department: attributes['department'] = department
    if phone: attributes['telephoneNumber'] = phone
    if computer_name: attributes['physicalDeliveryOfficeName'] = computer_name
    
    try:
        if not conn.add(user_dn, attributes=attributes):
            conn.unbind()
            return False, f"Ошибка создания: {conn.result.get('description', 'Unknown')}"
        ad_pw = f'"{password}"'.encode('utf-16-le')
        if not conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [ad_pw])]}):
            conn.delete(user_dn)
            conn.unbind()
            return False, "Пароль не удовлетворяет политикам."
        conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [512])], 'pwdLastSet': [(ldap3.MODIFY_REPLACE, ["-1"])]})
        if groups:
            for gdn in groups:
                conn.modify(gdn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        conn.unbind()
        res_msg = user_dn
        if ps_error:
            res_msg = f"{user_dn} (LDAP, PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        return False, str(e)

def delete_ad_user(username, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.delete_user(username)
        if success:
            return True, f"(PS) {message}"
        ps_error = message
        if mode == 'powershell':
            return False, f"PowerShell Error: {message}"

    ldap3 = _get_ldap3()
    if not ldap3: return False, "LDAP3 не установлен"
    conn, error = _get_connection(settings)
    if error: return False, error
    try:
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, "Пользователь не найден"
        user_dn = str(conn.entries[0].distinguishedName)
        success = conn.delete(user_dn)
        conn.unbind()
        res_msg = "Успешно удален" if success else "Ошибка удаления"
        if ps_error:
            res_msg = f"{res_msg} через LDAP (PS ошибка: {ps_error})"
        return success, res_msg
    except Exception as e:
        return False, str(e)

def update_ad_user_info(username, settings, data):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'LDAP Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        mapping = {'display_name': 'displayName', 'mail': 'mail', 'department': 'department', 'telephoneNumber': 'telephoneNumber'}
        search_filter = f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))'
        conn.search(settings.base_dn, search_filter, attributes=list(mapping.values()))
        if not conn.entries:
            conn.unbind()
            return False, 'Пользователь не найден'
        entry = conn.entries[0]
        changes = {}
        for key, ad_attr in mapping.items():
            if key in data:
                new_val = data[key].strip() if data[key] else ""
                current_ad_val = str(getattr(entry, ad_attr)) if hasattr(entry, ad_attr) and getattr(entry, ad_attr).value else ""
                if new_val != current_ad_val:
                    if new_val: changes[ad_attr] = [(ldap3.MODIFY_REPLACE, [new_val])]
                    elif current_ad_val: changes[ad_attr] = [(ldap3.MODIFY_DELETE, [])]
        if not changes:
            conn.unbind()
            return True, 'Нет изменений'
        success = conn.modify(entry.entry_dn, changes)
        conn.unbind()
        return success, 'Обновлено' if success else 'Ошибка AD'
    except Exception as e:
        return False, str(e)
