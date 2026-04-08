import json
from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user
from werkzeug.security import generate_password_hash

from utils import admin_required
from forms import AdminUserForm, ADUserCreateForm
from models import db, User, Ticket, ADSettings, Todo
from ad_service import (
    get_ad_containers, create_ad_user, 
    update_ad_user_info, set_ad_password_never_expires, get_user_ad_info
)
from . import admin_bp

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

from services.user_service import provision_ad_user, update_user_profile

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
        success, message = provision_ad_user(form, settings)
        if success:
            flash(message, 'success')
            return redirect(url_for('admin.users'))
        else:
            flash(f'Ошибка: {message}', 'danger')
            
    return render_template('admin/ad_user_form.html', form=form)

@admin_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)
    
    # Pre-fill "never expires" from AD on GET
    if request.method == 'GET' and user.is_from_ad:
        ad_settings = ADSettings.query.first()
        if ad_settings:
            ad_info, _ = get_user_ad_info(user.username, ad_settings)
            if ad_info:
                form.password_never_expires.data = ad_info.get('pwd_never_expires', False)

    if form.validate_on_submit():
        # Quick validation
        existing = User.query.filter(User.username.ilike(form.username.data)).first()
        if existing and existing.id != user.id:
            flash('Пользователь с таким логином уже существует', 'warning')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)
            
        if user.role == 'superadmin' and form.role.data != 'superadmin' and user.id == current_user.id:
            flash('Нельзя снять права суперадмина с самого себя!', 'danger')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)

        # Call the service
        ad_settings = ADSettings.query.first()
        success, message = update_user_profile(user, form, ad_settings)
        
        if success:
            flash(f'{message} и синхронизированы с AD', 'success')
            return redirect(url_for('admin.users'))
        else:
            flash(message, 'danger')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)
            
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
        
    has_history = (
        Ticket.query.filter((Ticket.author_id == user.id) | (Ticket.assignee_id == user.id)).count() > 0 or
        Todo.query.filter_by(user_id=user.id).count() > 0
    )
    
    if has_history:
        user.is_active = False
        db.session.commit()
        flash(f'У пользователя {user.display_name} есть история заявок. Он был деактивирован.', 'warning')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.display_name} успешно удален.', 'success')
        
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/<int:user_id>')
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    ad_info = None
    if user.is_from_ad:
        settings = ADSettings.query.first()
        ad_info, error = get_user_ad_info(user.username, settings)
        if error:
            flash(f'Ошибка AD: {error}', 'warning')
    return render_template('admin/user_detail.html', user=user, ad_info=ad_info)
