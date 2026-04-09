import json
from models import db, User
from ad_service import create_ad_user, update_ad_user_info, set_ad_password_never_expires
from ad_service.exchange import enable_mailbox

def provision_ad_user(form, settings):
    """
    Coordinates creation of a user in AD and then in the local DB.
    Also handles Exchange mailbox provisioning if requested and enabled.
    Returns (success, message)
    """
    groups_raw = form.groups_data.data
    groups_list = []
    if groups_raw:
        try:
            groups_list = json.loads(groups_raw)
        except Exception:
            pass
            
    success, result_message = create_ad_user(
        form.first_name.data,
        form.last_name.data,
        form.username.data,
        form.password.data,
        form.target_ou.data,
        groups_list,
        settings,
        email=form.email.data,
        department=form.department.data,
        phone=form.phone.data,
        computer_name=form.computer_name.data
    )
    
    if success:
        user = User(
            username=form.username.data.lower(),
            full_name=f"{form.last_name.data} {form.first_name.data}",
            role='employee',
            is_from_ad=True,
            is_active=True,
            email=form.email.data,
            department=form.department.data,
            phone=form.phone.data,
            computer_name=form.computer_name.data
        )
        db.session.add(user)
        db.session.commit()
        
        main_message = 'Пользователь успешно создан в Active Directory и базе данных!'
        
        # Provision Exchange Mailbox if requested
        if settings.is_exchange_enabled and form.create_mailbox.data:
            ex_success, ex_msg = enable_mailbox(
                form.username.data, 
                settings.exchange_server,
                admin_user=settings.bind_user,
                admin_password=settings.bind_password
            )
            if ex_success:
                main_message += f"\n✅ {ex_msg}"
            else:
                main_message += f"\n⚠️ Пользователь создан, но почта - нет: {ex_msg}"
        
        return True, main_message
    
    return False, result_message

def update_user_profile(user, form, settings):
    """
    Coordinates profile updates for both local DB and Active Directory.
    Returns (success, message)
    """
    # 1. Sync with AD if user is an AD account
    if user.is_from_ad and settings and settings.is_active:
        ad_data = {
            'display_name': form.full_name.data,
            'mail': form.email.data,
            'department': form.department.data,
            'telephoneNumber': form.phone.data
        }
        success, ad_message = update_ad_user_info(user.username, settings, ad_data)
        
        # We always set "never expires" flag (non-critical if it fails silently but logged in ad_service)
        set_ad_password_never_expires(user.username, form.password_never_expires.data, settings)
        
        if not success:
            return False, f'Ошибка AD: {ad_message}'

    # 2. Update local DB
    from werkzeug.security import generate_password_hash
    
    changes = []
    if user.username != form.username.data: changes.append(f"Логин: {user.username} -> {form.username.data}")
    if user.full_name != form.full_name.data: changes.append(f"ФИО: {user.full_name} -> {form.full_name.data}")
    if user.role != form.role.data: changes.append(f"Роль: {user.role} -> {form.role.data}")
    if user.is_active != form.is_active.data: changes.append(f"Активен: {user.is_active} -> {form.is_active.data}")
    
    user.username = form.username.data
    user.full_name = form.full_name.data
    user.role = form.role.data
    user.department = form.department.data
    user.phone = form.phone.data
    user.computer_name = form.computer_name.data
    user.email = form.email.data
    user.is_active = form.is_active.data
    user.is_from_ad = form.is_from_ad.data

    if form.password.data:
        user.password = generate_password_hash(form.password.data)
        changes.append("Локальный пароль обновлен")
    
    db.session.commit()
    change_text = "\n".join(changes) if changes else "без изменений"
    return True, f'Данные обновлены:\n{change_text}'
