from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user

from forms import TicketForm, AdminTicketForm
from models import db, Ticket, TicketStatus, Category, User, get_now, Article

tickets_bp = Blueprint('tickets', __name__, url_prefix='/tickets')

@tickets_bp.route('/')
@login_required
def index():
    status_name = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search = request.args.get('search')
    category_id = request.args.get('category', type=int)
    assignee_id = request.args.get('assignee', type=int)

    query = Ticket.query.order_by(Ticket.created_at.desc())

    if not current_user.is_admin:
        query = query.filter(Ticket.author_id == current_user.id)

    if status_name:
        status_obj = TicketStatus.query.filter_by(name=status_name).first()
        if status_obj:
            query = query.filter(Ticket.status_id == status_obj.id)

    if category_id:
        query = query.filter(Ticket.category_id == category_id)

    if assignee_id and current_user.is_admin:
        query = query.filter(Ticket.assignee_id == assignee_id)

    if start_date:
        query = query.filter(Ticket.created_at >= start_date)
    if end_date:
        query = query.filter(Ticket.created_at <= end_date + ' 23:59:59')

    if search:
        query = query.filter(
            (Ticket.description.ilike(f'%{search}%')) |
            (Ticket.resolution.ilike(f'%{search}%')) |
            (Ticket.contact_phone.ilike(f'%{search}%')) |
            (Ticket.contact_computer.ilike(f'%{search}%'))
        )

    tickets_list = query.all()
    statuses = TicketStatus.query.order_by(TicketStatus.name).all()
    categories = Category.query.order_by(Category.name).all()
    it_staff = User.query.filter_by(role='admin', is_active=True).all() if current_user.is_admin else []

    return render_template(
        'tickets.html',
        tickets=tickets_list,
        statuses=statuses,
        categories=categories,
        it_staff=it_staff,
        selected_status=status_name,
        selected_start=start_date,
        selected_end=end_date,
        selected_search=search,
        selected_category=category_id,
        selected_assignee=assignee_id
    )

@tickets_bp.route('/<int:ticket_id>')
@login_required
def view(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin and ticket.author_id != current_user.id:
        abort(403)
    statuses = TicketStatus.query.order_by(TicketStatus.name).all() if current_user.is_admin else []
    it_staff = User.query.filter_by(role='admin', is_active=True).all() if current_user.is_admin else []
    return render_template('ticket_view.html', ticket=ticket, statuses=statuses, it_staff=it_staff)

@tickets_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    is_admin = current_user.is_admin
    form = AdminTicketForm() if is_admin else TicketForm()

    if is_admin:
        # Populate full choices for admin
        form.author_id.choices = [(u.id, u.display_name) for u in User.query.filter_by(is_active=True).order_by(User.full_name).all()]
        form.category_id.choices = [(0, '— Без категории —')] + [(c.id, c.name) for c in Category.query.all()]
        it_staff = User.query.filter_by(role='admin', is_active=True).all() + User.query.filter_by(role='superadmin', is_active=True).all()
        # Deduplicate staff list and create choices
        staff_choices = [(u.id, u.display_name) for u in list(set(it_staff))]
        form.assignee_id.choices = [(0, '— Не назначено —')] + staff_choices
        form.status_id.choices = [(s.id, s.name) for s in TicketStatus.query.all()]
        form.article_id.choices = [(0, '— Нет статьи —')] + [(a.id, a.title) for a in Article.query.all()]
        
        if request.method == 'GET':
            form.author_id.data = current_user.id
            status_new = TicketStatus.query.filter_by(name='Новая').first()
            form.status_id.data = status_new.id if status_new else 0
            form.category_id.data = 0
            form.assignee_id.data = 0
            form.article_id.data = 0
    else:
        # User choices
        form.category_id.choices = [(0, '— Выберите категорию (опционально) —')] + [(c.id, c.name) for c in Category.query.all()]

    if request.method == 'GET':
        form.contact_phone.data = current_user.phone
        form.contact_computer.data = current_user.computer_name

    if form.validate_on_submit():
        if is_admin:
            status_obj = TicketStatus.query.get(form.status_id.data) if form.status_id.data != 0 else TicketStatus.query.filter_by(name='Новая').first()
            ticket = Ticket(
                author_id=form.author_id.data,
                category_id=form.category_id.data if form.category_id.data != 0 else None,
                description=form.description.data,
                resolution=form.resolution.data,
                contact_phone=form.contact_phone.data,
                contact_computer=form.contact_computer.data,
                status_id=status_obj.id if status_obj else None,
                assignee_id=form.assignee_id.data if form.assignee_id.data != 0 else None,
                article_id=form.article_id.data if form.article_id.data != 0 else None
            )
        else:
            status_new = TicketStatus.query.filter_by(name='Новая').first()
            cat = Category.query.get(form.category_id.data) if form.category_id.data != 0 else None
            
            ticket = Ticket(
                author_id=current_user.id,
                category_id=cat.id if cat else None,
                description=form.description.data,
                contact_phone=form.contact_phone.data,
                contact_computer=form.contact_computer.data,
                status_id=status_new.id if status_new else None,
                assignee_id=cat.assignee_id if cat and cat.assignee_id else None
            )
            
        db.session.add(ticket)
        db.session.commit()
        flash('Заявка успешно создана!', 'success')
        return redirect(url_for('tickets.index'))
        
    return render_template('ticket_form.html', form=form, is_admin_form=is_admin)

@tickets_bp.route('/<int:ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin:
        abort(403)
        
    form = AdminTicketForm(obj=ticket)
    
    # Populate full choices for admin
    form.author_id.choices = [(u.id, u.display_name) for u in User.query.filter_by(is_active=True).order_by(User.full_name).all()]
    form.category_id.choices = [(0, '— Без категории —')] + [(c.id, c.name) for c in Category.query.all()]
    it_staff = User.query.filter_by(role='admin', is_active=True).all() + User.query.filter_by(role='superadmin', is_active=True).all()
    # Deduplicate staff list and create choices
    staff_choices = [(u.id, u.display_name) for u in list(set(it_staff))]
    form.assignee_id.choices = [(0, '— Не назначено —')] + staff_choices
    form.status_id.choices = [(s.id, s.name) for s in TicketStatus.query.all()]
    form.article_id.choices = [(0, '— Нет статьи —')] + [(a.id, a.title) for a in Article.query.all()]
    
    if request.method == 'GET':
        form.author_id.data = ticket.author_id
        form.category_id.data = ticket.category_id or 0
        form.assignee_id.data = ticket.assignee_id or 0
        form.status_id.data = ticket.status_id or 0
        form.article_id.data = ticket.article_id or 0

    if form.validate_on_submit():
        ticket.author_id = form.author_id.data
        ticket.category_id = form.category_id.data if form.category_id.data != 0 else None
        ticket.description = form.description.data
        ticket.resolution = form.resolution.data
        ticket.contact_phone = form.contact_phone.data
        ticket.contact_computer = form.contact_computer.data
        
        # Check if status changed to resolved
        old_status = ticket.status_id
        ticket.status_id = form.status_id.data if form.status_id.data != 0 else None
        if ticket.status_id != old_status:
            status_obj = TicketStatus.query.get(ticket.status_id)
            if status_obj and status_obj.name == 'Решено':
                ticket.resolved_at = get_now()
            else:
                ticket.resolved_at = None
                
        ticket.assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
        ticket.article_id = form.article_id.data if form.article_id.data != 0 else None
        
        db.session.commit()
        flash('Заявка обновлена', 'success')
        return redirect(url_for('tickets.view', ticket_id=ticket.id))
    
    return render_template('ticket_form.html', form=form, edit=True, ticket=ticket, is_admin_form=True)

@tickets_bp.route('/<int:ticket_id>/delete')
@login_required
def delete(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin:
        abort(403)
    db.session.delete(ticket)
    db.session.commit()
    flash('Заявка удалена', 'success')
    return redirect(url_for('tickets.index'))

@tickets_bp.route('/<int:ticket_id>/set_status/<int:status_id>')
@login_required
def set_status(ticket_id, status_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin:
        abort(403)
    status_obj = TicketStatus.query.get_or_404(status_id)
    ticket.status_id = status_obj.id
    if status_obj.name == 'Решено':
        ticket.resolved_at = get_now()
    else:
        ticket.resolved_at = None
    db.session.commit()
    flash(f'Статус изменен на: {status_obj.name}', 'success')
    return redirect(url_for('tickets.view', ticket_id=ticket.id))
