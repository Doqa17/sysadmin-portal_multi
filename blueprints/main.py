from datetime import timedelta
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from models import db, Ticket, TicketStatus, Article, Todo
from forms import ProfileForm

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
@login_required
def index():
    if current_user.is_admin:
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.join(TicketStatus).filter(
            TicketStatus.name.in_(['Новая', 'В работе'])
        ).count()
        resolved_tickets = Ticket.query.join(TicketStatus).filter(
            TicketStatus.name == 'Решено'
        ).count()
        articles_count = Article.query.count()

        # Chart: avg tickets by weekday
        chart_labels = ['Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница']
        chart_data = [0, 0, 0, 0, 0]
        tickets_dates = db.session.query(Ticket.created_at).all()
        valid_dates = [t[0] for t in tickets_dates if t[0]]
        if valid_dates:
            min_d = min(valid_dates).date()
            max_d = max(valid_dates).date()
            day_totals = {i: 0 for i in range(5)}
            curr = min_d
            while curr <= max_d:
                if curr.weekday() < 5:
                    day_totals[curr.weekday()] += 1
                curr += timedelta(days=1)
            ticket_counts = {i: 0 for i in range(5)}
            for dt in valid_dates:
                w = dt.weekday()
                if w < 5:
                    ticket_counts[w] += 1
            for w in range(5):
                if day_totals[w] > 0:
                    chart_data[w] = round(ticket_counts[w] / day_totals[w], 1)

        # Recent tickets for admin
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(5).all()

        return render_template(
            'index.html',
            total_tickets=total_tickets,
            open_tickets=open_tickets,
            resolved_tickets=resolved_tickets,
            articles_count=articles_count,
            chart_labels=chart_labels,
            chart_data=chart_data,
            recent_tickets=recent_tickets,
        )
    else:
        # Employee dashboard
        my_tickets = Ticket.query.filter_by(author_id=current_user.id).order_by(Ticket.created_at.desc()).limit(5).all()
        my_open = Ticket.query.filter_by(author_id=current_user.id).join(TicketStatus).filter(
            TicketStatus.name.in_(['Новая', 'В работе'])
        ).count()
        my_total = Ticket.query.filter_by(author_id=current_user.id).count()
        my_todos_pending = Todo.query.filter_by(user_id=current_user.id, done=False).count()
        return render_template(
            'index.html',
            my_tickets=my_tickets,
            my_open=my_open,
            my_total=my_total,
            my_todos_pending=my_todos_pending,
        )

@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.full_name = form.full_name.data
        current_user.department = form.department.data
        current_user.phone = form.phone.data
        current_user.computer_name = form.computer_name.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Профиль обновлён', 'success')
        return redirect(url_for('main.profile'))
    return render_template('profile.html', form=form)
