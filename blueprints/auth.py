from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, ADSettings
from forms import LoginForm, RegisterForm
from ad_service import authenticate_ad

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.is_active:
            ad_settings = ADSettings.query.first()
            
            # --- 1. ЭКСТРЕННЫЙ ВХОД ДЛЯ ЛОКАЛЬНОГО АДМИНА ---
            # Оставляем лазейку только для системного администратора по локальному паролю
            if user.username == 'admin' or user.role == 'superadmin':
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('main.index'))

            # --- 2. КОРПОРАТИВНЫЙ ВХОД ЧЕРЕЗ AD (для всех остальных) ---
            if ad_settings and ad_settings.is_active:
                # Если пользователь из AD, проверяем пароль строго в AD
                if authenticate_ad(form.username.data, form.password.data, ad_settings):
                    login_user(user)
                    return redirect(url_for('main.index'))
                else:
                    flash('Ошибка входа: Неверные учетные данные Active Directory', 'danger')
                    return render_template('login.html', form=form)
            else:
                flash('Ошибка: Авторизация через Active Directory сейчас недоступна. Свяжитесь со старшим администратором.', 'warning')
                return render_template('login.html', form=form)

        flash('Доступ запрещен или неверные данные', 'danger')
        
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
