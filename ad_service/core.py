import ldap3
import logging

logger = logging.getLogger(__name__)

def _get_ldap3():
    return ldap3

def _get_connection(settings):
    """Internal helper to get a bound LDAP3 connection with StartTLS."""
    if not settings or not settings.server:
        return None, "Настройки AD не заданы"
    try:
        # Добавляем таймаут на подключение (3 секунды)
        server = ldap3.Server(settings.server, use_ssl=False, get_info=ldap3.ALL, connect_timeout=3)
        conn = ldap3.Connection(
            server, 
            user=settings.bind_user, 
            password=settings.bind_password, 
            authentication=ldap3.SIMPLE,
            auto_bind=False,
            receive_timeout=5 # Таймаут на получение данных
        )
        conn.open()
        # Использование StartTLS для безопасности паролей
        conn.start_tls()
        conn.bind()
        return conn, None
    except Exception as e:
        logger.error(f"AD Connection failed: {e}")
        return None, str(e)

def test_connection(settings):
    """Test the LDAP connection with given settings."""
    conn, error = _get_connection(settings)
    if error:
        return False, error
    conn.unbind()
    return True, "Соединение успешно установлено"

def _parse_ad_date(value):
    """Parse AD FILETIME (100-nanosecond intervals since Jan 1, 1601) to datetime."""
    import datetime
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    try:
        ival = int(str(value))
        if ival <= 0 or ival > 9223372036854775807:
            return None
        # Convert to microseconds and add to base date
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ival // 10)
    except Exception:
        return None

