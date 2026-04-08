from flask import render_template, redirect, url_for, flash, request
from utils import admin_required
from forms import CategoryForm
from models import db, User, Category, Ticket, TicketStatus
from . import admin_bp

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
