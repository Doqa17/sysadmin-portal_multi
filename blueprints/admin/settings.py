from flask import render_template, redirect, url_for, flash, request
from utils import admin_required, log_audit
from forms import ADSettingsForm, ExchangeSettingsForm
from models import db, User, ADSettings, AuditLog
from ad_service import test_connection, sync_users
from ad_service.exchange import test_exchange_connection
from . import admin_bp

@admin_bp.route('/admin/ad-settings', methods=['GET', 'POST'])
@admin_required
def ad_settings():
    settings = ADSettings.query.first()
    form = ADSettingsForm(obj=settings)
    if form.validate_on_submit():
        changes = []
        if settings.server != form.server.data: changes.append(f"Server: {settings.server} -> {form.server.data}")
        if settings.base_dn != form.base_dn.data: changes.append(f"Base DN: {settings.base_dn} -> {form.base_dn.data}")
        if settings.bind_user != form.bind_user.data: changes.append(f"User: {settings.bind_user} -> {form.bind_user.data}")
        if form.is_active.data != settings.is_active: changes.append(f"Active: {settings.is_active} -> {form.is_active.data}")
        if form.ad_modify_mode.data != settings.ad_modify_mode: changes.append(f"Mode: {settings.ad_modify_mode} -> {form.ad_modify_mode.data}")
        
        settings.server = form.server.data
        settings.base_dn = form.base_dn.data
        settings.bind_user = form.bind_user.data
        if form.bind_password.data:
            settings.bind_password = form.bind_password.data
            changes.append("Password updated")
        settings.search_filter = form.search_filter.data
        settings.timezone_offset = form.timezone_offset.data
        settings.ad_modify_mode = form.ad_modify_mode.data
        settings.is_active = form.is_active.data
        db.session.commit()
        
        desc = "Обновлены настройки AD:\n" + "\n".join(changes) if changes else "Настройки AD сохранены без изменений"
        log_audit('SETTINGS', desc)
        flash('Настройки AD обновлены', 'success')
        return redirect(url_for('admin.ad_settings'))
    return render_template('admin/ad_settings.html', form=form, settings=settings)


@admin_bp.route('/admin/exchange-settings', methods=['GET', 'POST'])
@admin_required
def exchange_settings():
    settings = ADSettings.query.first()
    if not settings:
        flash('Сначала настройте подключение к AD!', 'warning')
        return redirect(url_for('admin.ad_settings'))
        
    form = ExchangeSettingsForm(obj=settings)
    if form.validate_on_submit():
        changes = []
        if form.is_exchange_enabled.data != settings.is_exchange_enabled: 
            changes.append(f"Exchange Enabled: {settings.is_exchange_enabled} -> {form.is_exchange_enabled.data}")
        if form.exchange_server.data != settings.exchange_server: 
            changes.append(f"Exchange Server: {settings.exchange_server} -> {form.exchange_server.data}")
        
        settings.is_exchange_enabled = form.is_exchange_enabled.data
        settings.exchange_server = form.exchange_server.data
        db.session.commit()
        
        if changes:
            log_audit('SETTINGS', "Обновлены настройки Exchange:\n" + "\n".join(changes))
        flash('Настройки Microsoft Exchange обновлены', 'success')
        return redirect(url_for('admin.exchange_settings'))
        
    return render_template('admin/exchange_settings.html', form=form, settings=settings)


@admin_bp.route('/admin/exchange-test', methods=['POST'])
@admin_required
def exchange_test():
    settings = ADSettings.query.first()
    if not settings:
        flash('Настройки не найдены', 'warning')
        return redirect(url_for('admin.exchange_settings'))
        
    success, message = test_exchange_connection(settings)
    if success:
        flash(message, 'success')
    else:
        flash(f'Ошибка: {message}', 'danger')
    return redirect(url_for('admin.exchange_settings'))

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
    if not settings:
        flash('Настройки AD не заданы', 'warning')
        return redirect(url_for('admin.ad_settings'))
    created, updated, deactivated, errors = sync_users(settings, db, User)
    if errors:
        for e in errors:
            flash(f'⚠️ {e}', 'warning')
    
    msg = f'Синхронизация завершена: создано {created}, обновлено {updated}, деактивировано {deactivated}'
    log_audit('SYNC', msg)
    flash(msg, 'success')
    return redirect(url_for('admin.ad_settings'))

@admin_bp.route('/admin/logs')
@admin_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('admin/audit_logs.html', logs=logs)
