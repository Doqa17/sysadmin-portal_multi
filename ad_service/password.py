import logging
from .core import _get_ldap3, _get_connection

logger = logging.getLogger(__name__)

def change_ad_password(username, new_password, settings):
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
        
        # Для смены пароля AD требует "цитаты" и кодировку utf-16-le
        ad_pw = f'"{new_password}"'.encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [ad_pw])]})
        
        # Если пароль успешно сменен, сбрасываем флаг "сменить при входе" и разблокируем
        conn.modify(user_dn, {
            'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])],
            'lockoutTime': [(ldap3.MODIFY_REPLACE, [0])]
        })
        
        conn.unbind()
        return True, 'Пароль успешно изменен'
    except Exception as e:
        logger.error(f'AD password change failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'

def extend_ad_password(username, settings):
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
        # Установка pwdLastSet в -1 обновляет возраст пароля на текущий момент (продлевает срок)
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])]})
        conn.unbind()
        return True, 'Срок действия пароля продлен'
    except Exception as e:
        logger.error(f'AD password extend failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'

def unlock_ad_account(username, settings):
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
        return True, 'Аккаунт успешно разблокирован'
    except Exception as e:
        logger.error(f'AD unlock failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'

def force_password_change(username, settings):
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
        return True, 'При следующем входе пользователь обязан сменить пароль'
    except Exception as e:
        logger.error(f'AD force pwd change failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'

def set_ad_password_never_expires(username, never_expires, settings):
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
        
        # ADS_UF_DONT_EXPIRE_PASSWD = 65536
        if never_expires:
            new_uac = uac | 65536
        else:
            new_uac = uac & ~65536
            
        if uac != new_uac:
            conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
        
        conn.unbind()
        return True, f"Режим бессрочного пароля {'включен' if never_expires else 'выключен'}"
    except Exception as e:
        logger.error(f'AD toggle pwd expiration failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'
