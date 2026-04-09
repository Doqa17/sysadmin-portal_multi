import logging
from .core import _get_ldap3, _get_connection
from . import powershell

logger = logging.getLogger(__name__)

def _get_mode(settings):
    return getattr(settings, 'ad_modify_mode', 'auto').lower()

def remove_user_from_group(username, group_name, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        # Находим DN группы для PowerShell, если передано имя
        group_dn = group_name # Предполагаем, что это DN
        success, message = powershell.remove_from_group(username, group_dn)
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
            attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, f'Пользователь {username} не найден'
        user_dn = str(conn.entries[0].distinguishedName)
        
        conn.search(settings.base_dn, 
            f'(&(objectClass=group)(|(sAMAccountName={ldap3.utils.conv.escape_filter_chars(group_name)})(distinguishedName={ldap3.utils.conv.escape_filter_chars(group_name)})))',
            attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, f'Группа {group_name} не найдена'
        group_dn = str(conn.entries[0].distinguishedName)
        
        conn.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        conn.unbind()
        res_msg = f'Пользователь удален из группы {group_name}'
        if ps_error:
            res_msg = f"{res_msg} через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD group remove failed: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def search_ad_groups(query, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings or not settings.server:
        return [], 'Настройки AD недоступны'
    try:
        conn, error = _get_connection(settings)
        if error:
            return [], error
        
        search_filter = f'(&(objectClass=group)(|(sAMAccountName=*{ldap3.utils.conv.escape_filter_chars(query)}*)(displayName=*{ldap3.utils.conv.escape_filter_chars(query)}*)))'
        conn.search(settings.base_dn, search_filter, attributes=['sAMAccountName', 'distinguishedName', 'displayName'])
        
        results = []
        for entry in conn.entries:
            results.append({
                'cn': str(entry.displayName) if entry.displayName else str(entry.sAMAccountName),
                'dn': str(entry.distinguishedName)
            })
        
        conn.unbind()
        return results, None
    except Exception as e:
        logger.error(f'AD group search failed: {e}')
        return [], str(e)

def add_user_to_group(username, group_dn, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.add_to_group(username, group_dn)
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
            attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, f'Пользователь {username} не найден'
        user_dn = str(conn.entries[0].distinguishedName)
        
        conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        conn.unbind()
        res_msg = 'Пользователь успешно добавлен в группу'
        if ps_error:
            res_msg = f"{res_msg} через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        if 'entryAlreadyExists' in str(e):
            return True, 'Пользователь уже состоит в этой группе'
        logger.error(f'AD group add failed: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'
