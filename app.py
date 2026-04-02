import os
from functools import wraps
from datetime import timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import generate_csrf

from config import Config
from models import db, User, Article, Ticket, Category, TicketStatus, ArticleImage, Todo, ADSettings
from forms import (
    LoginForm, RegisterForm, ProfileForm, AdminUserForm,
    TicketForm, AdminTicketForm, CategoryForm, ArticleForm, ADSettingsForm
)
from ad_service import test_connection, sync_users, authenticate_ad

app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему'

# Make generate_csrf available as csrf_token() in all templates
app.jinja_env.globals['csrf_token'] = generate_csrf


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------- ROLE DECORATORS ----------

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Доступ запрещён. Требуются права администратора.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ---------- INITIAL DATA ----------

with app.app_context():
    db.create_all()

    # Default statuses
    default_statuses = [
        ('Новая', 'primary'),
        ('В работе', 'warning'),
        ('Решено', 'success'),
        ('Отложено', 'secondary'),
    ]
    for name, color in default_statuses:
        if not TicketStatus.query.filter_by(name=name).first():
            db.session.add(TicketStatus(name=name, color=color))

    # Default categories
    default_categories = [
        'Ремонт ПК',
        'Ремонт принтера',
        'Установка ПО',
        'Сеть и интернет',
        'Другое',
    ]
    for name in default_categories:
        if not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name))

    # Default admin
    if not User.query.first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            full_name='Главный администратор',
            role='superadmin',
            is_active=True
        )
        db.session.add(admin)
    db.session.commit()


# ---------- AUTH ----------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.is_active:
            # Try AD auth first if enabled and user is from AD
            if user.is_from_ad:
                ad_settings = ADSettings.query.first()
                if ad_settings and ad_settings.is_active:
                    if authenticate_ad(form.username.data, form.password.data, ad_settings):
                        login_user(user)
                        return redirect(url_for('index'))
                    else:
                        flash('Неверный логин или пароль')
                        return render_template('login.html', form=form)
            # Local auth
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
        flash('Неверный логин или пароль')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Пользователь с таким логином уже существует')
            return render_template('register.html', form=form)
        user = User(
            username=form.username.data,
            password=generate_password_hash(form.password.data),
            full_name=form.full_name.data,
            role='employee',
            department=form.department.data,
            phone=form.phone.data,
            computer_name=form.computer_name.data,
            email=form.email.data,
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Войдите в систему.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------- PROFILE ----------

@app.route('/profile', methods=['GET', 'POST'])
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
        flash('Профиль обновлён')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)


# ---------- DASHBOARD ----------

@app.route('/')
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


# ---------- TICKETS ----------

@app.route('/tickets')
@login_required
def tickets():
    status_name = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search = request.args.get('search')
    category_id = request.args.get('category', type=int)
    assignee_id = request.args.get('assignee', type=int)

    query = Ticket.query.order_by(Ticket.created_at.desc())

    # Non-admins see only their own tickets
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
        search_query=search,
        current_status=status_name,
        current_category=category_id,
        current_assignee=assignee_id,
        start_date=start_date,
        end_date=end_date,
    )


@app.route('/tickets/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not current_user.is_admin and ticket.author_id != current_user.id:
        abort(403)
    statuses = TicketStatus.query.order_by(TicketStatus.name).all()
    return render_template('ticket_view.html', ticket=ticket, statuses=statuses)


@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if current_user.is_admin:
        form = AdminTicketForm()
        form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
        it_users = User.query.filter_by(role='admin', is_active=True).all()
        form.assignee_id.choices = [(0, '— Автоматически —')] + [(u.id, u.display_name) for u in it_users]
        form.status_id.choices = [(s.id, s.name) for s in TicketStatus.query.all()]
        form.article_id.choices = [(0, '— Не связано —')] + [(a.id, a.title) for a in Article.query.all()]

        if form.validate_on_submit():
            category = Category.query.get(form.category_id.data)
            assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
            if not assignee_id and category and category.assignee_id:
                assignee_id = category.assignee_id

            ticket = Ticket(
                description=form.description.data,
                resolution=form.resolution.data,
                author_id=current_user.id,
                assignee_id=assignee_id,
                contact_phone=form.contact_phone.data,
                contact_computer=form.contact_computer.data,
                category_id=form.category_id.data,
                status_id=form.status_id.data,
                article_id=form.article_id.data if form.article_id.data != 0 else None,
            )
            db.session.add(ticket)
            db.session.commit()
            flash('Заявка создана')
            return redirect(url_for('tickets'))
        # Pre-fill contact info
        if request.method == 'GET':
            form.contact_phone.data = current_user.phone
            form.contact_computer.data = current_user.computer_name
        return render_template('ticket_form.html', form=form, edit=False, is_admin_form=True)
    else:
        form = TicketForm()
        form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]

        if form.validate_on_submit():
            category = Category.query.get(form.category_id.data)
            new_status = TicketStatus.query.filter_by(name='Новая').first()
            if not new_status:
                new_status = TicketStatus.query.first()

            ticket = Ticket(
                description=form.description.data,
                author_id=current_user.id,
                assignee_id=category.assignee_id if category else None,
                contact_phone=form.contact_phone.data or current_user.phone,
                contact_computer=form.contact_computer.data or current_user.computer_name,
                category_id=form.category_id.data,
                status_id=new_status.id,
            )
            db.session.add(ticket)
            db.session.commit()
            flash('Заявка успешно подана! Мы свяжемся с вами в ближайшее время.')
            return redirect(url_for('tickets'))

        if request.method == 'GET':
            form.contact_phone.data = current_user.phone
            form.contact_computer.data = current_user.computer_name
        return render_template('ticket_form.html', form=form, edit=False, is_admin_form=False)


@app.route('/tickets/<int:ticket_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    form = AdminTicketForm(obj=ticket)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    it_users = User.query.filter_by(role='admin', is_active=True).all()
    form.assignee_id.choices = [(0, '— Не назначено —')] + [(u.id, u.display_name) for u in it_users]
    form.status_id.choices = [(s.id, s.name) for s in TicketStatus.query.all()]
    form.article_id.choices = [(0, '— Не связано —')] + [(a.id, a.title) for a in Article.query.all()]

    if form.validate_on_submit():
        ticket.description = form.description.data
        ticket.resolution = form.resolution.data
        ticket.contact_phone = form.contact_phone.data
        ticket.contact_computer = form.contact_computer.data
        ticket.category_id = form.category_id.data
        ticket.status_id = form.status_id.data
        ticket.assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
        ticket.article_id = form.article_id.data if form.article_id.data != 0 else None
        db.session.commit()
        flash('Заявка обновлена')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))

    if request.method == 'GET':
        form.category_id.data = ticket.category_id
        form.status_id.data = ticket.status_id
        form.assignee_id.data = ticket.assignee_id or 0
        form.article_id.data = ticket.article_id or 0

    return render_template('ticket_form.html', form=form, edit=True, ticket=ticket, is_admin_form=True)


@app.route('/tickets/<int:ticket_id>/delete')
@admin_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash('Заявка удалена')
    return redirect(url_for('tickets'))


@app.route('/tickets/<int:ticket_id>/set_status/<int:status_id>')
@admin_required
def set_ticket_status(ticket_id, status_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    status = TicketStatus.query.get_or_404(status_id)
    ticket.status_id = status.id
    db.session.commit()
    flash(f"Статус заявки обновлён на «{status.name}»")
    return redirect(request.referrer or url_for('tickets'))


# ---------- ARTICLES ----------

@app.route('/articles')
@login_required
def articles():
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', type=str)
    query = Article.query.order_by(Article.created_at.desc())
    if category_id:
        query = query.filter(Article.category_id == category_id)
    if search:
        query = query.filter(
            (Article.title.ilike(f'%{search}%')) |
            (Article.problem.ilike(f'%{search}%')) |
            (Article.solution.ilike(f'%{search}%'))
        )
    articles_list = query.all()
    categories = Category.query.order_by(Category.name).all()
    return render_template(
        'articles.html',
        articles=articles_list,
        categories=categories,
        selected_category=category_id,
        search_query=search
    )


@app.route('/articles/new', methods=['GET', 'POST'])
@admin_required
def new_article():
    form = ArticleForm()
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]
    if form.validate_on_submit():
        article = Article(
            title=form.title.data,
            problem=form.problem.data,
            solution=form.solution.data,
            category_id=form.category.data
        )
        db.session.add(article)
        db.session.commit()
        if form.images.data:
            for file in form.images.data:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    db.session.add(ArticleImage(filename=filename, article_id=article.id))
        db.session.commit()
        flash('Статья добавлена')
        return redirect(url_for('articles'))
    return render_template('article_form.html', form=form)


@app.route('/articles/<int:article_id>')
@login_required
def view_article(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template('article_view.html', article=article)


@app.route('/articles/<int:article_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_article(article_id):
    article = Article.query.get_or_404(article_id)
    form = ArticleForm(obj=article)
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]
    if request.method == 'GET':
        form.category.data = article.category_id
    if form.validate_on_submit():
        article.title = form.title.data
        article.problem = form.problem.data
        article.solution = form.solution.data
        article.category_id = form.category.data
        deleted_ids = request.form.getlist('deleted_images')
        if deleted_ids:
            for img_id in deleted_ids:
                img = ArticleImage.query.get(int(img_id))
                if img:
                    img_path = os.path.join(app.config['UPLOAD_FOLDER'], img.filename)
                    if os.path.exists(img_path):
                        os.remove(img_path)
                    db.session.delete(img)
        if form.images.data:
            for file in form.images.data:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    db.session.add(ArticleImage(filename=filename, article_id=article.id))
        db.session.commit()
        flash('Статья обновлена')
        return redirect(url_for('view_article', article_id=article.id))
    return render_template('article_form.html', form=form, edit=True, article=article)


@app.route('/articles/<int:article_id>/delete')
@admin_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    for img in article.images:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], img.filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(article)
    db.session.commit()
    flash('Статья удалена')
    return redirect(url_for('articles'))


@app.route('/articles/image/<int:image_id>/delete', methods=['POST'])
@admin_required
def delete_article_image(image_id):
    image = ArticleImage.query.get_or_404(image_id)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
    if os.path.exists(image_path):
        os.remove(image_path)
    db.session.delete(image)
    db.session.commit()
    flash('Изображение удалено')
    return redirect(url_for('edit_article', article_id=image.article_id))


# ---------- TODOS (per-user) ----------

@app.route('/todos')
@login_required
def todos():
    status_filter = request.args.get('status')
    query = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.desc())
    if status_filter == 'done':
        query = query.filter(Todo.done.is_(True))
    elif status_filter == 'pending':
        query = query.filter(Todo.done.is_(False))
    todos_list = query.all()
    return render_template('todos.html', todos=todos_list, status_filter=status_filter)


@app.route('/todos/new', methods=['GET', 'POST'])
@login_required
def new_todo():
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        if not description:
            flash('Описание задачи не может быть пустым')
            return redirect(url_for('new_todo'))
        todo = Todo(description=description, user_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
        flash('Задача добавлена!')
        return redirect(url_for('todos'))
    return render_template('todo_form.html')


@app.route('/todos/<int:todo_id>/toggle')
@login_required
def toggle_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        abort(403)
    todo.done = not todo.done
    db.session.commit()
    return redirect(url_for('todos'))


@app.route('/todos/<int:todo_id>/delete')
@login_required
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    db.session.delete(todo)
    db.session.commit()
    flash('Задача удалена')
    return redirect(url_for('todos'))


@app.route('/todos/<int:todo_id>')
@login_required
def view_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return render_template('todo_view.html', todo=todo)


@app.route('/todos/<int:todo_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        todo.description = request.form['description']
        todo.done = 'done' in request.form
        db.session.commit()
        flash('Задача обновлена')
        return redirect(url_for('todos'))
    return render_template('todo_form.html', todo=todo, edit=True)


# ---------- ADMIN: USERS ----------

@app.route('/admin/users')
@admin_required
def admin_users():
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
    users = query.all()
    return render_template('admin/users.html', users=users, search=search, role_filter=role_filter)


@app.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def admin_new_user():
    form = AdminUserForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Пользователь с таким логином уже существует')
            return render_template('admin/user_form.html', form=form)
        if not form.password.data:
            flash('Пароль обязателен при создании пользователя')
            return render_template('admin/user_form.html', form=form)
            
        # ROLE PROTECTION: Admin cannot create Superadmin
        if form.role.data == 'superadmin' and not current_user.is_superadmin:
            flash('Только старший администратор может создавать других суперадминов!')
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
        flash('Пользователь создан')
        return redirect(url_for('admin_users'))
    return render_template('admin/user_form.html', form=form, edit=False)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminUserForm(obj=user)
    if form.validate_on_submit():
        existing = User.query.filter_by(username=form.username.data).first()
        if existing and existing.id != user.id:
            flash('Пользователь с таким логином уже существует')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)
        # ROLE PROTECTION: Self-edit protection for superadmin
        if user.id == current_user.id and form.role.data != user.role:
            flash('Вы не можете менять свою собственную роль!')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)

        # ROLE PROTECTION: Admin cannot demote other admins/superadmins
        if not current_user.is_superadmin and user.role in ('admin', 'superadmin') and form.role.data == 'employee':
            flash('У вас нет прав на понижение администратора до обычного сотрудника!')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)
        
        # ROLE PROTECTION: Admin cannot promote to superadmin
        if not current_user.is_superadmin and form.role.data == 'superadmin' and user.role != 'superadmin':
            flash('Вы не имеете права назначать роль суперадмина!')
            return render_template('admin/user_form.html', form=form, edit=True, user=user)

        user.username = form.username.data
        user.full_name = form.full_name.data
        user.role = form.role.data
        user.department = form.department.data
        user.phone = form.phone.data
        user.computer_name = form.computer_name.data
        user.email = form.email.data
        user.is_active = form.is_active.data
        user.is_from_ad = form.is_from_ad.data

        if form.password.data:
            user.password = generate_password_hash(form.password.data)
            user.is_from_ad = False  # If admin set a custom password, user becomes local
        
        db.session.commit()
        flash('Пользователь обновлён')
        return redirect(url_for('admin_users'))
    return render_template('admin/user_form.html', form=form, edit=True, user=user)


@app.route('/admin/users/<int:user_id>/delete')
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Нельзя удалить собственную учётную запись')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь удалён')
    return redirect(url_for('admin_users'))


# ---------- ADMIN: CATEGORIES ----------

@app.route('/categories')
@admin_required
def categories():
    cats = Category.query.order_by(Category.name).all()
    return render_template('categories.html', categories=cats)


@app.route('/categories/new', methods=['GET', 'POST'])
@admin_required
def new_category():
    form = CategoryForm()
    it_users = User.query.filter_by(role='admin', is_active=True).all()
    form.assignee_id.choices = [(0, '— Не назначено —')] + [(u.id, u.display_name) for u in it_users]
    if form.validate_on_submit():
        if Category.query.filter_by(name=form.name.data).first():
            flash('Такая категория уже существует')
        else:
            cat = Category(
                name=form.name.data,
                assignee_id=form.assignee_id.data if form.assignee_id.data != 0 else None
            )
            db.session.add(cat)
            db.session.commit()
            flash('Категория добавлена')
            return redirect(url_for('categories'))
    return render_template('category_form.html', form=form)


@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
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
            flash('Такая категория уже существует')
        else:
            category.name = form.name.data
            category.assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
            db.session.commit()
            flash('Категория обновлена')
            return redirect(url_for('categories'))
    return render_template('category_form.html', form=form, edit=True)


@app.route('/categories/<int:category_id>/delete')
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if Ticket.query.filter_by(category_id=category_id).first():
        flash('Невозможно удалить категорию — есть связанные заявки')
        return redirect(url_for('categories'))
    db.session.delete(category)
    db.session.commit()
    flash('Категория удалена')
    return redirect(url_for('categories'))


# ---------- ADMIN: STATUSES ----------

@app.route('/statuses')
@admin_required
def statuses():
    all_statuses = TicketStatus.query.order_by(TicketStatus.name).all()
    return render_template('statuses.html', statuses=all_statuses)


@app.route('/statuses/new', methods=['GET', 'POST'])
@admin_required
def new_status():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'secondary')
        if name and not TicketStatus.query.filter_by(name=name).first():
            db.session.add(TicketStatus(name=name, color=color))
            db.session.commit()
            flash('Статус добавлен')
            return redirect(url_for('statuses'))
    return render_template('status_form.html')


@app.route('/statuses/<int:status_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_status(status_id):
    status = TicketStatus.query.get_or_404(status_id)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'secondary')
        if name:
            existing = TicketStatus.query.filter_by(name=name).first()
            if existing and existing.id != status.id:
                flash('Статус с таким именем уже существует')
            else:
                status.name = name
                status.color = color
                db.session.commit()
                flash('Статус обновлён')
                return redirect(url_for('statuses'))
    return render_template('status_form.html', status=status, edit=True)


@app.route('/statuses/<int:status_id>/delete')
@admin_required
def delete_status(status_id):
    status = TicketStatus.query.get_or_404(status_id)
    if status.tickets:
        flash('Невозможно удалить статус — есть заявки с этим статусом')
        return redirect(url_for('statuses'))
    db.session.delete(status)
    db.session.commit()
    flash('Статус удалён')
    return redirect(url_for('statuses'))


# ---------- ADMIN: ACTIVE DIRECTORY ----------

@app.route('/admin/ad-settings', methods=['GET', 'POST'])
@admin_required
def ad_settings():
    settings = ADSettings.query.first()
    if not settings:
        settings = ADSettings()
        db.session.add(settings)
        db.session.commit()
    form = ADSettingsForm(obj=settings)
    if form.validate_on_submit():
        settings.server = form.server.data or ''
        settings.base_dn = form.base_dn.data or ''
        settings.bind_user = form.bind_user.data or ''
        if form.bind_password.data:
            settings.bind_password = form.bind_password.data
        settings.search_filter = form.search_filter.data or settings.search_filter
        settings.is_active = form.is_active.data
        db.session.commit()
        flash('Настройки AD сохранены')
        return redirect(url_for('ad_settings'))
    return render_template('admin/ad_settings.html', form=form, settings=settings)


@app.route('/admin/ad-test', methods=['POST'])
@admin_required
def ad_test():
    settings = ADSettings.query.first()
    ok, msg = test_connection(settings)
    if ok:
        flash(f'✅ {msg}', 'success')
    else:
        flash(f'❌ {msg}', 'danger')
    return redirect(url_for('ad_settings'))


@app.route('/admin/ad-sync', methods=['POST'])
@admin_required
def ad_sync():
    settings = ADSettings.query.first()
    created, updated, deactivated, errors = sync_users(settings, db, User)
    if errors:
        for e in errors:
            flash(f'⚠️ {e}', 'warning')
    flash(f'Синхронизация завершена: создано {created}, обновлено {updated}, деактивировано {deactivated}', 'success')
    return redirect(url_for('ad_settings'))


# ---------- ERROR HANDLERS ----------

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)