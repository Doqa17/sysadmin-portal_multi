from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user

from models import db, Todo

todos_bp = Blueprint('todos', __name__, url_prefix='/todos')

@todos_bp.route('/')
@login_required
def index():
    status_filter = request.args.get('status')
    query = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.desc())
    if status_filter == 'done':
        query = query.filter(Todo.done.is_(True))
    elif status_filter == 'pending':
        query = query.filter(Todo.done.is_(False))
    todos_list = query.all()
    return render_template('todos.html', todos=todos_list, status_filter=status_filter)

@todos_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        if not description:
            flash('Описание задачи не может быть пустым', 'warning')
            return redirect(url_for('todos.new'))
        todo = Todo(description=description, user_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
        flash('Задача добавлена!', 'success')
        return redirect(url_for('todos.index'))
    return render_template('todo_form.html')

@todos_bp.route('/<int:todo_id>/toggle')
@login_required
def toggle(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        abort(403)
    todo.done = not todo.done
    db.session.commit()
    return redirect(url_for('todos.index'))

@todos_bp.route('/<int:todo_id>/delete')
@login_required
def delete(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    db.session.delete(todo)
    db.session.commit()
    flash('Задача удалена', 'success')
    return redirect(url_for('todos.index'))

@todos_bp.route('/<int:todo_id>')
@login_required
def view(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return render_template('todo_view.html', todo=todo)

@todos_bp.route('/<int:todo_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        todo.description = request.form['description']
        todo.done = 'done' in request.form
        db.session.commit()
        flash('Задача обновлена', 'success')
        return redirect(url_for('todos.index'))
    return render_template('todo_form.html', todo=todo, edit=True)
