from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user, login_required

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Доступ запрещён. Требуются права администратора.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated
