from functools import wraps
from flask import flash, redirect, url_for, request
from flask_login import current_user, login_required
from models import db, AuditLog

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Доступ запрещён. Требуются права администратора.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated

def log_audit(action, description, target=None):
    """Helper to record administrative actions to the database."""
    try:
        log_entry = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            target=target,
            description=description,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        # We don't want to crash the whole app if logging fails, 
        # but we should at least try to log the error to the file
        from flask import current_app
        current_app.logger.error(f"Failed to record audit log: {e}")
        db.session.rollback()
