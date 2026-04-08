from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime

db = SQLAlchemy()


def get_now():
    """Централизованная функция получения времени с учетом часового пояса из настроек."""
    from models import ADSettings
    try:
        settings = ADSettings.query.first()
        offset = settings.timezone_offset if settings and settings.timezone_offset is not None else 8
    except:
        offset = 8
    
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=offset)))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True) # Позволяет AD-пользователям быть без локального пароля
    full_name = db.Column(db.String(150))
    role = db.Column(db.String(20), default='employee')  # 'superadmin', 'admin' or 'employee'
    department = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    computer_name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    is_from_ad = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    password_never_expires = db.Column(db.Boolean, default=False)
    password_prefix = db.Column(db.String(100))

    @property
    def is_admin(self):
        return self.role in ('admin', 'superadmin')

    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

    @property
    def display_name(self):
        return self.full_name or self.username

    def get_id(self):
        return str(self.id)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id], backref='assigned_categories')

    articles = db.relationship('Article', backref='category', lazy=True)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    problem = db.Column(db.Text, nullable=False)
    solution = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    created_at = db.Column(db.DateTime, default=get_now)

    images = db.relationship(
        'ArticleImage',
        backref='article',
        cascade='all, delete-orphan',
        lazy=True
    )


class ArticleImage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    article_id = db.Column(
        db.Integer,
        db.ForeignKey('article.id', ondelete='CASCADE'),
        nullable=False
    )


class TicketStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(30), default='secondary')  # bootstrap color class

    tickets = db.relationship('Ticket', backref='status_obj', lazy=True)

    def __repr__(self):
        return f'<TicketStatus {self.name}>'


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    resolution = db.Column(db.Text)

    # Who submitted
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', foreign_keys=[author_id], backref='submitted_tickets')

    # Who is assigned (auto from category)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id], backref='assigned_tickets')

    # Contact info snapshot
    contact_phone = db.Column(db.String(20))
    contact_computer = db.Column(db.String(100))

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', backref='tickets')

    status_id = db.Column(db.Integer, db.ForeignKey('ticket_status.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=get_now)

    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=True)
    article = db.relationship('Article', backref='tickets')


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='todos')


class ADSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server = db.Column(db.String(200), default='')
    base_dn = db.Column(db.String(200), default='')
    bind_user = db.Column(db.String(200), default='')
    bind_password = db.Column(db.String(200), default='')
    search_filter = db.Column(
        db.String(300),
        default='(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    )
    timezone_offset = db.Column(db.Integer, default=8) # Новое поле для часового пояса
    is_active = db.Column(db.Boolean, default=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=get_now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='actions')
    
    action = db.Column(db.String(50), nullable=False)  # 'PASSWORD', 'POWER', 'SYNC', 'SETTINGS', 'ACCOUNT'
    target = db.Column(db.String(100))  # Username or Computer name
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))  # IPv6 compatible

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id} at {self.timestamp}>'
