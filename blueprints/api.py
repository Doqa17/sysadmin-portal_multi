import socket
import subprocess
import random
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from utils import admin_required
from models import db, User, ADSettings, Ticket, Todo
from ad_service import (
    delete_ad_user, unlock_ad_account, toggle_ad_account, 
    search_ad_groups, add_user_to_group, remove_user_from_group,
    change_ad_password, extend_ad_password, set_ad_password_never_expires
)

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/user/<int:user_id>')
@admin_required
def user_info(user_id):
    """API for getting user contact info to auto-fill ticket form."""
    user = User.query.get_or_404(user_id)
    return jsonify({
        'phone': user.phone or '',
        'computer_name': user.computer_name or '',
        'display_name': user.display_name,
    })

@api_bp.route('/tools/ping', methods=['POST'])
@admin_required
def ping():
    """Ping a computer by name or IP."""
    computer = request.json.get('computer', '').strip()
    if not computer:
        return jsonify({'alive': False, 'error': 'Имя компьютера не указано'})
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '1500', computer],
            capture_output=True, text=True, timeout=5
        )
        alive = result.returncode == 0
        return jsonify({'alive': alive, 'computer': computer})
    except Exception as e:
        return jsonify({'alive': False, 'error': str(e)})

@api_bp.route('/tools/change-password', methods=['POST'])
@admin_required
def change_password():
    """Change AD user password: manual or (prefix + 3 random digits)."""
    user_id = request.json.get('user_id')
    manual_password = request.json.get('manual_password', '').strip()
    prefix = request.json.get('prefix', '').strip()
    
    if not user_id:
        return jsonify({'success': False, 'message': 'Пользователь не указан'})

    if not manual_password and not prefix:
        return jsonify({'success': False, 'message': 'Укажите префикс или готовый пароль'})

    user = User.query.get_or_404(user_id)
    settings = ADSettings.query.first()
    
    if not settings or not settings.is_active:
        return jsonify({'success': False, 'message': 'AD не настроена или отключена'})

    # Определяем итоговый пароль
    if manual_password:
        new_password = manual_password
    else:
        suffix = str(random.randint(0, 999)).zfill(3)
        new_password = prefix + suffix

    success, message = change_ad_password(user.username, new_password, settings)

    if success:
        user.password_prefix = prefix
        db.session.commit()

    return jsonify({'success': success, 'message': message, 'new_password': new_password if success else None})

@api_bp.route('/tools/extend-password', methods=['POST'])
@admin_required
def extend_password():
    """Extend AD password expiry by resetting pwdLastSet to now."""
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Не указан ID пользователя'})

    user = User.query.get_or_404(user_id)
    if user.password_never_expires:
        return jsonify({'success': False, 'message': 'Пользователь имеет постоянный пароль'})

    settings = ADSettings.query.first()
    success, message = extend_ad_password(user.username, settings)
    return jsonify({'success': success, 'message': message})

@api_bp.route('/tools/delete-ad-account', methods=['POST'])
@admin_required
def delete_ad_account():
    if not current_user.is_superadmin:
        return jsonify({'success': False, 'message': 'Доступ запрещен: требуется роль Суперадмина'})
        
    user_id = request.json.get('user_id')
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Невозможно удалить самого себя'})
        
    settings = ADSettings.query.first()
    success, message = delete_ad_user(user.username, settings)
    
    if success or "Пользователь не найден в AD" in message:
        # Check for historical records locally
        has_history = (
            Ticket.query.filter((Ticket.author_id == user.id) | (Ticket.assignee_id == user.id)).count() > 0 or
            Todo.query.filter_by(user_id=user.id).count() > 0
        )
        
        if has_history:
            user.is_active = False
            user.is_from_ad = False # It's no longer an AD user as we deleted it there
            db.session.commit()
            return jsonify({
                'success': True, 
                'message': 'Учетная запись удалена из Active Directory. На портале она переведена в статус "Заблокирован" для сохранения истории заявок.'
            })
        else:
            db.session.delete(user)
            db.session.commit()
            return jsonify({
                'success': True, 
                'message': 'Учетная запись полностью удалена и из AD, и с портала.'
            })
        
    return jsonify({'success': False, 'message': message})

@api_bp.route('/tools/unlock-account', methods=['POST'])
@admin_required
def unlock_account():
    user_id = request.json.get('user_id')
    user = User.query.get_or_404(user_id)
    settings = ADSettings.query.first()
    success, message = unlock_ad_account(user.username, settings)
    return jsonify({'success': success, 'message': message})

@api_bp.route('/tools/toggle-account', methods=['POST'])
@admin_required
def toggle_account():
    user_id = request.json.get('user_id')
    user = User.query.get_or_404(user_id)
    enable = not user.is_active
    
    if user.is_from_ad:
        settings = ADSettings.query.first()
        success, message = toggle_ad_account(user.username, enable, settings)
        if not success:
            return jsonify({'success': False, 'message': message})
            
    user.is_active = enable
    db.session.commit()
    return jsonify({'success': True, 'message': f"Пользователь {'включён' if enable else 'отключён'}"})

@api_bp.route('/tools/toggle-password-expiration', methods=['POST'])
@admin_required
def toggle_password_expiration():
    user_id = request.json.get('user_id')
    never_expires = request.json.get('never_expires') # boolean
    user = User.query.get_or_404(user_id)
    
    if not user.is_from_ad:
        return jsonify({'success': False, 'message': 'Только для пользователей из Active Directory'})
        
    settings = ADSettings.query.first()
    success, message = set_ad_password_never_expires(user.username, never_expires, settings)
    
    return jsonify({'success': success, 'message': message})

@api_bp.route('/tools/search-groups', methods=['GET'])
@admin_required
def search_groups():
    query = request.args.get('q', '')
    if len(query) < 2: return jsonify([])
    settings = ADSettings.query.first()
    results, error = search_ad_groups(query, settings)
    return jsonify(results)

@api_bp.route('/tools/add-to-group', methods=['POST'])
@admin_required
def add_to_group():
    user_id = request.json.get('user_id')
    group_dn = request.json.get('group_dn')
    user = User.query.get_or_404(user_id)
    settings = ADSettings.query.first()
    success, message = add_user_to_group(user.username, group_dn, settings)
    return jsonify({'success': success, 'message': message})

@api_bp.route('/tools/remove-from-group', methods=['POST'])
@admin_required
def remove_from_group():
    user_id = request.json.get('user_id')
    group_name = request.json.get('group_name')
    user = User.query.get_or_404(user_id)
    settings = ADSettings.query.first()
    success, message = remove_user_from_group(user.username, group_name, settings)
    return jsonify({'success': success, 'message': message})

@api_bp.route('/tools/ping-pc', methods=['POST'])
@login_required
def ping_pc():
    computer_name = request.json.get('computer_name', '').strip()
    if not computer_name:
        return jsonify({'online': False})
    
    try:
        # Пингуем через систему: -n 1 (1 пакет), -w 1000 (таймаут 1 сек)
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '1000', computer_name],
            capture_output=True, text=True, timeout=3
        )
        online = (result.returncode == 0)
        return jsonify({'online': online})
    except Exception as e:
        return jsonify({'online': False, 'error': str(e)})
