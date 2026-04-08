import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import generate_csrf
from werkzeug.security import generate_password_hash

from config import Config
from models import db, User, TicketStatus, Category, ADSettings

login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Configure Logging
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=1024 * 1024, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Sysadmin Portal Startup')

    db.init_app(app)
    
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Пожалуйста, войдите в систему'
    
    # Make generate_csrf available as csrf_token() in all templates
    app.jinja_env.globals['csrf_token'] = generate_csrf

    # Register Blueprints
    from blueprints.auth import auth_bp
    from blueprints.main import main_bp
    from blueprints.tickets import tickets_bp
    from blueprints.articles import articles_bp
    from blueprints.todos import todos_bp
    from blueprints.admin import admin_bp
    from blueprints.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(articles_bp)
    app.register_blueprint(todos_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # Initialize data
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
            
        # Default AD Settings
        if not ADSettings.query.first():
            new_filter = '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=HealthMailbox*)))'
            db.session.add(ADSettings(search_filter=new_filter))
            
        db.session.commit()

    return app
