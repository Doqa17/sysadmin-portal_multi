import ldap3
import logging
from flask import flash

logger = logging.getLogger(__name__)

def _get_ldap3():
    return ldap3

def _get_connection(settings):
    if not settings or not settings.server:
        return None, "Настройки AD не заданы"
    try:
        server = ldap3.Server(settings.server, use_ssl=False, get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server, 
            user=settings.bind_user, 
            password=settings.bind_password, 
            authentication=ldap3.SIMPLE,
            auto_bind=False
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
    conn, error = _get_connection(settings)
    if error:
        return False, error
    conn.unbind()
    return True, "Соединение успешно установлено"

def sync_users(settings, db, User):
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

def authenticate_ad(username, password, settings):
    ldap3 = _get_ldap3()
    if not ldap3: return False
    
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
            
        return False
    except Exception:
        return False

def change_ad_password(username, new_password, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, 'User not found'
        
        user_dn = str(conn.entries[0].distinguishedName)
        success = conn.extend.microsoft.modify_password(user_dn, new_password=new_password)
        conn.unbind()
        if success:
            return True, 'Пароль успешно изменен'
        return False, 'Не удалось изменить пароль (проверьте политики сложности)'
    except Exception as e:
        return False, str(e)

def extend_ad_password(username, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, 'User not found'
        
        user_dn = str(conn.entries[0].distinguishedName)
        # Сброс pwdLastSet в -1 (устанавливает текущее время)
        conn.modify(user_dn, {'pwdLastSet': [(ldap3.MODIFY_REPLACE, [-1])]})
        conn.unbind()
        return True, 'Срок действия пароля продлен'
    except Exception as e:
        return False, str(e)

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

def toggle_ad_account(username, enable, settings):
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
        return True, f'Аккаунт успешно {action} в AD'
    except Exception as e:
        logger.error(f'AD toggle account failed for {username}: {e}')
        return False, f'Ошибка: {str(e)}'


def set_ad_password_never_expires(username, never_expires, settings):
    """
    Включает или выключает флаг "Срок действия пароля не ограничен" (UAC bit 65536).
    """
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        
        search_filter = f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))'
        conn.search(settings.base_dn, search_filter, attributes=['distinguishedName', 'userAccountControl'])
        
        if not conn.entries:
            conn.unbind()
            return False, 'Пользователь не найден в AD'
            
        user_dn = str(conn.entries[0].distinguishedName)
        uac = int(str(conn.entries[0].userAccountControl)) if conn.entries[0].userAccountControl else 512
        
        # Бит 65536 (0x10000) - DONT_EXPIRE_PASSWORD
        if never_expires:
            new_uac = uac | 65536
        else:
            new_uac = uac & ~65536
            
        success = conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
        conn.unbind()
        
        if success:
            action = "бессрочным" if never_expires else "обычным"
            return True, f'Пароль успешно сделан {action}'
        return False, 'Не удалось изменить статус пароля'
    except Exception as e:
        return False, str(e)

def _parse_ad_date(value):
    import datetime
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    try:
        ival = int(str(value))
        if ival <= 0 or ival > 9223372036854775807:
            return None
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ival // 10)
    except:
        return None

def get_user_ad_info(username, settings):
    import datetime
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
        
        # Берем максимальное из lastLogon (реальное время) и lastLogonTimestamp (реплицируемое)
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

def remove_user_from_group(username, group_name, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries: return False, 'Пользователь не найден'
        user_dn = str(conn.entries[0].distinguishedName)
        
        conn.search(settings.base_dn, f'(&(objectClass=group)(cn={ldap3.utils.conv.escape_filter_chars(group_name)}))', attributes=['distinguishedName'])
        if not conn.entries: return False, 'Группа не найдена'
        group_dn = str(conn.entries[0].distinguishedName)
        
        conn.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        conn.unbind()
        return True, f'Пользователь удален из группы {group_name}'
    except Exception as e:
        return False, str(e)

def search_ad_groups(query, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return [], 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return [], error
        
        filter = f'(&(objectClass=group)(cn=*{ldap3.utils.conv.escape_filter_chars(query)}*))'
        conn.search(settings.base_dn, filter, attributes=['cn', 'distinguishedName'])
        
        results = [{'cn': str(e.cn), 'dn': str(e.distinguishedName)} for e in conn.entries]
        conn.unbind()
        return results, None
    except Exception as e:
        return [], str(e)

def add_user_to_group(username, group_dn, settings):
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'AD Error'
    try:
        conn, error = _get_connection(settings)
        if error: return False, error
        
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries: return False, 'Пользователь не найден'
        user_dn = str(conn.entries[0].distinguishedName)
        
        conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        conn.unbind()
        return True, 'Пользователь успешно добавлен в группу'
    except Exception as e:
        return False, str(e)

def get_ad_containers(settings):
    """
    Возвращает список всех OU и контейнеров для выбора расположения нового пользователя.
    """
    ldap3 = _get_ldap3()
    if not ldap3: return []
    
    conn, error = _get_connection(settings)
    if error: return []
    
    try:
        # Ищем и папки (OU) и встроенные контейнеры (например CN=Users)
        filter_query = '(|(objectClass=organizationalUnit)(objectClass=container))'
        conn.search(settings.base_dn, filter_query, attributes=['name', 'distinguishedName'])
        
        results = []
        for entry in conn.entries:
            dn = str(entry.distinguishedName)
            # Отсеиваем системные контейнеры, чтобы не засорять список
            if any(x in dn for x in ['CN=System,', 'CN=Configuration,', 'CN=LostAndFound,', 'CN=Infrastructure,', 'CN=ForeignSecurityPrincipals,']):
                continue
            name = str(getattr(entry, 'name', dn))
            results.append({'name': name, 'dn': dn})
            
        conn.unbind()
        # Сортируем для красоты
        return sorted(results, key=lambda x: x['name'])
    except Exception:
        return []

def create_ad_user(first_name, last_name, username, password, target_ou, groups, settings, email=None, department=None, phone=None, computer_name=None):
    """
    Создает пользователя в указанном OU, устанавливает пароль и включает учетную запись.
    """
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
        'userAccountControl': 514,  # Создаем отключенной (512 + 2)
    }
    
    if email: attributes['mail'] = email
    if department: attributes['department'] = department
    if phone: attributes['telephoneNumber'] = phone
    if computer_name: attributes['physicalDeliveryOfficeName'] = computer_name
    
    try:
        # Шаг 1: Создаем учетную запись (отключенную)
        if not conn.add(user_dn, attributes=attributes):
            conn.unbind()
            return False, f"Ошибка создания учетки: {conn.result.get('description', 'Unknown')}"
            
        # Шаг 2: Установка пароля
        ad_pw = f'"{password}"'.encode('utf-16-le')
        if not conn.modify(user_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, [ad_pw])]}):
            error_desc = conn.result.get('description', 'Unknown')
            # ОТКАТ: Удаляем созданную пустую учетку!
            conn.delete(user_dn)
            conn.unbind()
            if 'unwillingToPerform' in error_desc:
                return False, "Пароль не удовлетворяет политикам сложности домена или соединение не использует SSL/TLS. Учетная запись отменена и удалена."
            return False, f"Ошибка установки пароля: {error_desc}. Учетная запись отменена и удалена."
            
        # Шаг 3: Включение учетки (меняем 514 на 512) и утверждение пароля (без требования сменить при входе)
        if not conn.modify(user_dn, {
            'userAccountControl': [(ldap3.MODIFY_REPLACE, [512])],
            'pwdLastSet': [(ldap3.MODIFY_REPLACE, ["-1"])]
        }):
            error_desc = conn.result.get('description', 'Unknown')
            conn.delete(user_dn)  # ОТКАТ
            conn.unbind()
            return False, f"Не удалось активировать учетную запись: {error_desc}. Учетная запись отменена и удалена."
        
        # Шаг 4: Добавление в группы
        if groups:
            for group_dn in groups:
                if not conn.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]}):
                    # Если даже группа не добавилась - лучше откатить
                    error_desc = conn.result.get('description', 'Unknown')
                    conn.delete(user_dn)  # ОТКАТ
                    conn.unbind()
                    return False, f"Не удалось добавить в группу {group_dn}: {error_desc}. Учетная запись отменена и удалена."
                
        conn.unbind()
        return True, user_dn
    except Exception as e:
        # Если скрипт упал по исключению, пытаемся удалить, если объект уже был создан
        try:
            conn.delete(user_dn)
        except:
            pass
        return False, str(e)

def delete_ad_user(username, settings):
    """Полностью удаляет пользователя из Active Directory."""
    ldap3 = _get_ldap3()
    if not ldap3: return False, "LDAP3 не установлен"
    
    conn, error = _get_connection(settings)
    if error: return False, error
    
    try:
        conn.search(settings.base_dn, f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))', attributes=['distinguishedName'])
        if not conn.entries:
            conn.unbind()
            return False, "Пользователь не найден в AD"
        user_dn = str(conn.entries[0].distinguishedName)
        
        if conn.delete(user_dn):
            conn.unbind()
            return True, "Пользователь успешно удален из AD"
        else:
            error_desc = conn.result.get('description', 'Unknown')
            conn.unbind()
            return False, f"Ошибка удаления: {error_desc}"
    except Exception as e:
        return False, str(e)


def update_ad_user_info(username, settings, data):
    """
    Обновляет данные пользователя в Active Directory, только если они изменились.
    """
    ldap3 = _get_ldap3()
    if not ldap3 or not settings: return False, 'Ошибка инициализации LDAP'
    
    try:
        conn, error = _get_connection(settings)
        if error: return False, f'Ошибка подключения к AD: {error}'
        
        # 1. Сначала читаем ТЕКУЩИЕ данные из AD
        mapping = {
            'display_name': 'displayName',
            'mail': 'mail',
            'department': 'department',
            'telephoneNumber': 'telephoneNumber'
        }
        
        search_filter = f'(&(objectClass=user)(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)}))'
        conn.search(settings.base_dn, search_filter, attributes=list(mapping.values()))
        
        if not conn.entries:
            conn.unbind()
            return False, 'Пользователь не найден в Active Directory'
            
        entry = conn.entries[0]
        user_dn = entry.entry_dn
        
        # 2. Сравниваем и готовим только РЕАЛЬНЫЕ изменения
        changes = {}
        for key, ad_attr in mapping.items():
            if key in data:
                new_val = data[key].strip() if data[key] else ""
                # Получаем текущее значение из AD (может быть пустым списком или строкой)
                current_ad_val = str(getattr(entry, ad_attr)) if hasattr(entry, ad_attr) and getattr(entry, ad_attr).value else ""
                
                if new_val != current_ad_val:
                    if new_val:
                        # Значение изменилось на непустое -> Заменяем
                        changes[ad_attr] = [(ldap3.MODIFY_REPLACE, [new_val])]
                    elif current_ad_val:
                        # Значение стерто И оно было непустым в AD -> Удаляем
                        changes[ad_attr] = [(ldap3.MODIFY_DELETE, [])]
            
        if not changes:
            conn.unbind()
            return True, 'Изменений не обнаружено'
            
        # 3. Применяем только то, что действительно нужно
        success = conn.modify(user_dn, changes)
        result_desc = conn.result.get("description", "Unknown error")
        message = 'Данные в Active Directory успешно обновлены' if success else f'AD Error: {result_desc}'
        
        conn.unbind()
        return success, message
        
    except Exception as e:
        return False, f'Критическая ошибка AD: {str(e)}'
