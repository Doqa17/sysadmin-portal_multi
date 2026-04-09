import logging
from .core import _get_ldap3, _get_connection
from . import powershell

logger = logging.getLogger(__name__)

def _get_mode(settings):
    return getattr(settings, 'ad_modify_mode', 'auto').lower()

def change_ad_password(username, new_password, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.change_password(username, new_password)
        if success:
            return True, f"(PS) {message}"
        ps_error = message
        if mode == 'powershell':
            return False, f"PowerShell Error: {message}"
            
    # Fallback or LDAP mode
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
            return False, f'Пользователь {username} не найден в AD'
        user_dn = str(conn.entries[0].distinguishedName)
        
        ad_pw = f'"{new_password}"'.encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [ad_pw])]})
        
        conn.modify(user_dn, {
            'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])],
            'lockoutTime': [(ldap3.MODIFY_REPLACE, [0])]
        })
        
        conn.unbind()
        res_msg = 'Пароль успешно изменен'
        if ps_error:
            res_msg = f"Пароль изменен через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD password change failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def extend_ad_password(username, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.extend_password(username)
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
            return False, f'Пользователь {username} не найден в AD'
        user_dn = str(conn.entries[0].distinguishedName)
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])]})
        conn.unbind()
        res_msg = 'Срок действия пароля продлен'
        if ps_error:
            res_msg = f"Продлено через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD password extend failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def unlock_ad_account(username, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.unlock_account(username)
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
            return False, f'Пользователь {username} не найден в AD'
        user_dn = str(conn.entries[0].distinguishedName)
        conn.modify(user_dn, {'lockoutTime': [(ldap3.MODIFY_REPLACE, [0])]})
        conn.unbind()
        res_msg = 'Аккаунт успешно разблокирован'
        if ps_error:
            res_msg = f"Разблокировано через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD unlock failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def force_password_change(username, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.force_password_change(username)
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
            return False, f'Пользователь {username} не найден в AD'
        user_dn = str(conn.entries[0].distinguishedName)
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [0])]})
        conn.unbind()
        res_msg = 'При следующем входе пользователь обязан сменить пароль'
        if ps_error:
            res_msg = f"Применено через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD force pwd change failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

def set_ad_password_never_expires(username, never_expires, settings):
    mode = _get_mode(settings)
    ps_error = None
    
    if mode in ['powershell', 'auto']:
        success, message = powershell.set_password_never_expires(username, never_expires)
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
        
        if never_expires:
            new_uac = uac | 65536
        else:
            new_uac = uac & ~65536
            
        if uac != new_uac:
            conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
        
        conn.unbind()
        res_msg = f"Режим бессрочного пароля {'включен' if never_expires else 'выключен'}"
        if ps_error:
            res_msg = f"{res_msg} через LDAP (PS ошибка: {ps_error})"
        return True, res_msg
    except Exception as e:
        logger.error(f'AD toggle pwd expiration failed for {username}: {e}')
        return False, f'Ошибка (LDAP): {str(e)}'

