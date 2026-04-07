import json
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from utils import admin_required
from forms import AdminUserForm, ADUserCreateForm, CategoryForm, ADSettingsForm
from models import db, User, Category, Ticket, TicketStatus, ADSettings, Todo
from ad_service import (
    get_ad_containers, create_ad_user, sync_users, 
    test_connection, update_ad_user_info, set_ad_password_never_expires
)

admin_bp = Blueprint('admin', __name__)

# ---------- USERS ----------

@admin_bp.route('/admin/users')
@admin_required
def users():
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    query = User.query.order_by(User.full_name, User.username)
    if search:
        query = query.filter(
            (User.username.ilike(f'%{search}%')) |
            (User.full_name.ilike(f'%{search}%')) |
            (User.department.ilike(f'%{search}%'))
        )
    if role_filter:
        query = query.filter(User.role == role_filter)
    users_list = query.all()
    return render_template('admin/users.html', users=users_list, search=search, role_filter=role_filter)

@admin_bp.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def new_user():
    form = AdminUserForm()
    if form.validate_on_submit():
        if User.query.filter(User.username.ilike(form.username.data)).first():
            flash('Пользователь с таким логином уже существует', 'warning')
            return render_template('admin/user_form.html', form=form)
        if not form.password.data:
            flash('Пароль обязателен при создании пользователя', 'warning')
            return render_template('admin/user_form.html', form=form)
            
        if form.role.data == 'superadmin' and not current_user.is_superadmin:
            flash('Только старший администратор может создавать других суперадминов!', 'danger')
            return render_template('admin/user_form.html', form=form)
            
        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            full_name=form.full_name.data,
            role=form.role.data,
            department=form.department.data,
            phone=form.phone.data,
            computer_name=form.computer_name.data,
            email=form.email.data,
            is_from_ad=form.is_from_ad.data,
            is_active=form.is_active.data,
        )
        db.session.add(user)
        db.session.commit()
        flash('Пользователь создан', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', form=form, edit=False)

@admin_bp.route('/admin/users/new-ad', methods=['GET', 'POST'])
@admin_required
def new_ad_user():
    form = ADUserCreateForm()
    
    settings = ADSettings.query.first()
    if not settings or not settings.base_dn:
        flash('Сначала настройте параметры Active Directory!', 'warning')
        return redirect(url_for('admin.users'))
        
    containers = get_ad_containers(settings)
    form.target_ou.choices = [(c['dn'], c['name']) for c in containers]
    
    if form.validate_on_submit():
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
            
            flash('Пользователь успешно создан в Active Directory!', 'success')
            return redirect(url_for('admin.users'))
        else:
            flash(f'Ошибка создания в AD: {result_message}', 'danger')
            
    return render_template('admin/ad_user_form.html', form=form)

@admin_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)
    
    # --- Предзаполнение данных из AD при загрузке (GET) ---
    if request.method == 'GET' and user.is_from_ad:
        from ad_service import get_user_ad_info
        ad_settings = ADSettings.query.first()
        if ad_settings:
            ad_info, _ = get_user_ad_info(user.username, ad_settings)
            if ad_info:
                form.password_never_expires.data = ad_info.get('pwd_never_expires', False)

    if form.validate_on_submit():
        existing = User.query.filter(User.username.ilike(form.username.data)).first()
        if existing and existing.id != user.id:
            flash('Пользователь с таким логином уже существует', 'warning')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)
            
        if user.role == 'superadmin' and form.role.data != 'superadmin' and user.id == current_user.id:
            flash('Нельзя снять права суперадмина с самого себя!', 'danger')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)

        # --- Синхронизация с Active Directory ---
        if user.is_from_ad:
            ad_settings = ADSettings.query.first()
            if ad_settings and ad_settings.is_active:
                # 1. Обновляем основные атрибуты
                ad_data = {
                    'display_name': form.full_name.data,
                    'mail': form.email.data,
                    'department': form.department.data,
                    'telephoneNumber': form.phone.data
                }
                success, ad_message = update_ad_user_info(user.username, ad_settings, ad_data)
                
                # 2. Обновляем статус бессрочности пароля
                set_ad_password_never_expires(user.username, form.password_never_expires.data, ad_settings)
                
                if not success:
                    flash(f'Ошибка обновления в Active Directory: {ad_message}. Данные не сохранены.', 'danger')
                    return render_template('admin/user_form.html', form=form, edit=True, user=user)

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
        
        db.session.commit()
        flash('Данные успешно обновлены и синхронизированы с AD', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', form=form, edit=True, user=user)

@admin_bp.route('/admin/users/<int:user_id>/delete')
@admin_required
def delete_user(user_id):
    if not current_user.is_superadmin:
        flash('Доступ запрещен: Только суперадмин может удалять учетные записи', 'danger')
        return redirect(url_for('admin.users'))
        
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Нельзя удалить собственную учётную запись', 'danger')
        return redirect(url_for('admin.users'))
        
    # Check for historical records
    # If the user has tickets (as author or assignee) or tasks, we deactivate instead of deleting to keep DB integrity
    has_history = (
        Ticket.query.filter((Ticket.author_id == user.id) | (Ticket.assignee_id == user.id)).count() > 0 or
        Todo.query.filter_by(user_id=user.id).count() > 0
    )
    
    if has_history:
        user.is_active = False
        db.session.commit()
        flash(f'У пользователя {user.display_name} есть история заявок/задач. Он был деактивирован (заблокирован) вместо полного удаления.', 'warning')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.display_name} успешно удален (истории не было).', 'success')
        
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    from ad_service import get_user_ad_info
    user = User.query.get_or_404(user_id)
    ad_info = None
    if user.is_from_ad:
        settings = ADSettings.query.first()
        ad_info, error = get_user_ad_info(user.username, settings)
        if error:
            flash(f'Ошибка AD: {error}', 'warning')
    return render_template('admin/user_detail.html', user=user, ad_info=ad_info)


# ---------- CATEGORIES ----------

@admin_bp.route('/categories')
@admin_required
def categories():
    all_categories = Category.query.order_by(Category.name).all()
    return render_template('categories.html', categories=all_categories)

@admin_bp.route('/categories/new', methods=['GET', 'POST'])
@admin_required
def new_category():
    form = CategoryForm()
    it_users = User.query.filter_by(role='admin', is_active=True).all()
    form.assignee_id.choices = [(0, '— Не назначено —')] + [(u.id, u.display_name) for u in it_users]
    if form.validate_on_submit():
        if Category.query.filter_by(name=form.name.data).first():
            flash('Такая категория уже существует', 'warning')
        else:
            cat = Category(
                name=form.name.data,
                assignee_id=form.assignee_id.data if form.assignee_id.data != 0 else None
            )
            db.session.add(cat)
            db.session.commit()
            flash('Категория добавлена', 'success')
            return redirect(url_for('admin.categories'))
    return render_template('category_form.html', form=form)

@admin_bp.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = CategoryForm(obj=category)
    it_users = User.query.filter_by(role='admin', is_active=True).all()
    form.assignee_id.choices = [(0, '— Не назначено —')] + [(u.id, u.display_name) for u in it_users]
    if request.method == 'GET':
        form.assignee_id.data = category.assignee_id or 0
    if form.validate_on_submit():
        existing = Category.query.filter_by(name=form.name.data).first()
        if existing and existing.id != category.id:
            flash('Такая категория уже существует', 'warning')
        else:
            category.name = form.name.data
            category.assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
            db.session.commit()
            flash('Категория обновлена', 'success')
            return redirect(url_for('admin.categories'))
    return render_template('category_form.html', form=form, edit=True)

@admin_bp.route('/categories/<int:category_id>/delete')
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if Ticket.query.filter_by(category_id=category_id).first():
        flash('Невозможно удалить категорию — есть связанные заявки', 'danger')
        return redirect(url_for('admin.categories'))
    db.session.delete(category)
    db.session.commit()
    flash('Категория удалена', 'success')
    return redirect(url_for('admin.categories'))


# ---------- STATUSES ----------

@admin_bp.route('/statuses')
@admin_required
def statuses():
    all_statuses = TicketStatus.query.order_by(TicketStatus.name).all()
    return render_template('statuses.html', statuses=all_statuses)

@admin_bp.route('/statuses/new', methods=['GET', 'POST'])
@admin_required
def new_status():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'primary')
        if not name:
            flash('Название не может быть пустым', 'warning')
        elif TicketStatus.query.filter_by(name=name).first():
            flash('Такой статус уже существует', 'warning')
        else:
            db.session.add(TicketStatus(name=name, color=color))
            db.session.commit()
            flash('Статус добавлен', 'success')
            return redirect(url_for('admin.statuses'))
    return render_template('status_form.html')

@admin_bp.route('/statuses/<int:status_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_status(status_id):
    status_obj = TicketStatus.query.get_or_404(status_id)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'primary')
        if not name:
            flash('Название не может быть пустым', 'warning')
        else:
            existing = TicketStatus.query.filter_by(name=name).first()
            if existing and existing.id != status_obj.id:
                flash('Такой статус уже существует', 'warning')
            else:
                status_obj.name = name
                status_obj.color = color
                db.session.commit()
                flash('Статус обновлён', 'success')
                return redirect(url_for('admin.statuses'))
    return render_template('status_form.html', status=status_obj, edit=True)

@admin_bp.route('/statuses/<int:status_id>/delete')
@admin_required
def delete_status(status_id):
    status_obj = TicketStatus.query.get_or_404(status_id)
    if Ticket.query.filter_by(status_id=status_id).first():
        flash('Невозможно удалить статус — есть связанные заявки', 'danger')
        return redirect(url_for('admin.statuses'))
    db.session.delete(status_obj)
    db.session.commit()
    flash('Статус удалён', 'success')
    return redirect(url_for('admin.statuses'))


# ---------- AD SETTINGS ----------

@admin_bp.route('/admin/ad-settings', methods=['GET', 'POST'])
@admin_required
def ad_settings():
    settings = ADSettings.query.first()
    form = ADSettingsForm(obj=settings)
    if form.validate_on_submit():
        if not settings:
            settings = ADSettings()
            db.session.add(settings)
        settings.server = form.server.data
        settings.domain = form.domain.data
        settings.base_dn = form.base_dn.data
        settings.bind_user = form.bind_user.data
        if form.bind_password.data:
            settings.bind_password = form.bind_password.data
        settings.search_filter = form.search_filter.data
        settings.timezone_offset = form.timezone_offset.data
        settings.is_active = form.is_active.data
        db.session.commit()
        flash('Настройки AD обновлены', 'success')
        return redirect(url_for('admin.ad_settings'))
    return render_template('admin/ad_settings.html', form=form, settings=settings)

@admin_bp.route('/admin/ad-test', methods=['POST'])
@admin_required
def ad_test():
    settings = ADSettings.query.first()
    if not settings:
        flash('Настройки не найдены', 'warning')
        return redirect(url_for('admin.ad_settings'))
    success, message = test_connection(settings)
    if success:
        flash(f'Успех: {message}', 'success')
    else:
        flash(f'Ошибка: {message}', 'danger')
    return redirect(url_for('admin.ad_settings'))

@admin_bp.route('/admin/ad-sync', methods=['POST'])
@admin_required
def ad_sync():
    settings = ADSettings.query.first()
    created, updated, deactivated, errors = sync_users(settings, db, User)
    if errors:
        for e in errors:
            flash(f'⚠️ {e}', 'warning')
    flash(f'Синхронизация завершена: создано {created}, обновлено {updated}, деактивировано {deactivated}', 'success')
    return redirect(url_for('admin.ad_settings'))
