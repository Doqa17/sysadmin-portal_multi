from .core import _get_ldap3, _get_connection

def authenticate_ad(username, password, settings):
    """Authenticate a user against AD using their username and password."""
    ldap3 = _get_ldap3()
    if not ldap3: 
        return False
    
    if not settings or not settings.server:
        return False
        
    # Двухэтапная аутентификация (наиболее надежный способ)
    # Шаг 1. Сервисная учетная запись логинится, чтобы найти полный DN пользователя
    conn, error = _get_connection(settings)
    if error:
        return False
        
    try:
        search_filter = f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))'
        conn.search(settings.base_dn, search_filter, attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False
            
        user_dn = str(conn.entries[0].distinguishedName)
        conn.unbind()
        
        # Шаг 2. Пытаемся залогиниться под найденным полным путем пользователя
        user_conn = ldap3.Connection(conn.server, user=user_dn, password=password, authentication=ldap3.SIMPLE)
        if user_conn.bind():
            user_conn.unbind()
            return True
            
        user_conn.unbind()
        return False
    except Exception:
        return False
