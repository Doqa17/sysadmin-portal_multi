from flask_wtf import FlaskForm
from wtforms import (
    StringField, TextAreaField, PasswordField, SubmitField,
    SelectField, MultipleFileField, BooleanField, EmailField,
    IntegerField, HiddenField
)
from wtforms.validators import DataRequired, Length, Optional, Email, EqualTo
from flask_wtf.file import FileAllowed


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=50)])
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password2 = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password', message='Пароли не совпадают')])
    department = StringField('Отдел', validators=[Optional(), Length(max=100)])
    phone = StringField('Телефон (стационарный)', validators=[Optional(), Length(max=20)])
    computer_name = StringField('Имя компьютера', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Зарегистрироваться')


class ProfileForm(FlaskForm):
    full_name = StringField('ФИО', validators=[DataRequired(), Length(max=150)])
    department = StringField('Отдел', validators=[Optional(), Length(max=100)])
    phone = StringField('Телефон (стационарный)', validators=[Optional(), Length(max=20)])
    computer_name = StringField('Имя компьютера', validators=[Optional(), Length(max=100)])
    email = StringField('Email', validators=[Optional(), Length(max=120)])
    password = PasswordField('Новый пароль (оставьте пустым, чтобы не менять)', validators=[Optional()])
    password2 = PasswordField('Повторите новый пароль', validators=[Optional(), EqualTo('password', message='Пароли не совпадают')])
    submit = SubmitField('Сохранить')


class AdminUserForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=50)])
    full_name = StringField('ФИО', validators=[Optional(), Length(max=150)])
    role = SelectField('Роль', choices=[
        ('employee', 'Сотрудник'),
        ('admin', 'Администратор (IT)'),
        ('superadmin', 'Старший администратор (Super)')
    ])
    department = StringField('Отдел', validators=[Optional(), Length(max=100)])
    phone = StringField('Телефон', validators=[Optional(), Length(max=20)])
    computer_name = StringField('Имя компьютера', validators=[Optional(), Length(max=100)])
    email = StringField('Email', validators=[Optional(), Length(max=120)])
    password = PasswordField('Пароль', validators=[Optional()])
    is_from_ad = BooleanField('Из Active Directory', default=False)
    password_never_expires = BooleanField('Пароль не имеет срока действия (AD)', default=False)
    is_active = BooleanField('Активен', default=True)
    submit = SubmitField('Сохранить')


class TicketForm(FlaskForm):
    category_id = SelectField('Категория', coerce=int, validators=[Optional()])
    description = TextAreaField('Описание проблемы', validators=[DataRequired()])
    contact_phone = StringField('Телефон для связи', validators=[Optional(), Length(max=20)])
    contact_computer = StringField('Имя компьютера', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Отправить заявку')


class AdminTicketForm(FlaskForm):
    author_id = SelectField('От имени пользователя', coerce=int, validators=[DataRequired()])
    category_id = SelectField('Категория', coerce=int, validators=[Optional()])
    description = TextAreaField('Описание проблемы', validators=[DataRequired()])
    resolution = TextAreaField('Решение', validators=[Optional()])
    contact_phone = StringField('Телефон для связи', validators=[Optional(), Length(max=20)])
    contact_computer = StringField('Имя компьютера', validators=[Optional(), Length(max=100)])
    assignee_id = SelectField('Исполнитель', coerce=int, validators=[Optional()])
    status_id = SelectField('Статус', coerce=int, validators=[DataRequired()])
    article_id = SelectField('Связанная статья', coerce=int, validators=[Optional()])
    submit = SubmitField('Сохранить')


class CategoryForm(FlaskForm):
    name = StringField('Название категории', validators=[DataRequired(), Length(max=100)])
    assignee_id = SelectField('Ответственный IT-сотрудник', coerce=int, validators=[Optional()])
    submit = SubmitField('Сохранить')


class ArticleForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    problem = TextAreaField('Проблема', validators=[DataRequired()])
    solution = TextAreaField('Решение', validators=[DataRequired()])
    images = MultipleFileField('Изображения', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Только изображения!')
    ])
    category = SelectField('Категория', coerce=int)
    submit = SubmitField('Сохранить')


class ADSettingsForm(FlaskForm):
    server = StringField('LDAP сервер', validators=[Optional(), Length(max=200)],
                         render_kw={'placeholder': 'ldap://dc.company.local'})
    base_dn = StringField('Base DN', validators=[Optional(), Length(max=200)],
                          render_kw={'placeholder': 'DC=company,DC=local'})
    bind_user = StringField('Bind User (DN)', validators=[Optional(), Length(max=200)],
                            render_kw={'placeholder': 'CN=ldap_reader,DC=company,DC=local'})
    bind_password = PasswordField('Bind Password', validators=[Optional()])
    search_filter = StringField('Фильтр поиска', validators=[Optional(), Length(max=300)])
    timezone_offset = IntegerField('Часовой пояс', default=8, render_kw={'placeholder': 'Например, 3 для МСК'})
    ad_modify_mode = SelectField('Режим записи в AD', choices=[
        ('ldap', 'Только LDAP (Режим совместимости)'),
        ('powershell', 'Только PowerShell (Максимальная надежность)'),
        ('auto', 'Автоматический (PowerShell с откатом на LDAP)')
    ], default='auto')
    
    is_active = BooleanField('Использовать AD для аутентификации', default=True)
    submit = SubmitField('Сохранить')


class ExchangeSettingsForm(FlaskForm):
    is_exchange_enabled = BooleanField('Включить интеграцию с Microsoft Exchange')
    exchange_server = StringField('Сервер Exchange (FQDN/IP)', validators=[Optional(), Length(max=255)],
                                  render_kw={'placeholder': 'например, mail.company.local'})
    submit = SubmitField('Сохранить настройки Exchange')



class ADUserCreateForm(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Фамилия', validators=[DataRequired(), Length(max=50)])
    username = StringField('Логин (по-английски)', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Начальный пароль', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])
    department = StringField('Отдел', validators=[Optional(), Length(max=100)])
    phone = StringField('Телефон', validators=[Optional(), Length(max=20)])
    computer_name = StringField('Имя ПК', validators=[Optional(), Length(max=50)])
    target_ou = SelectField('Расположение (OU / Папка)', validators=[DataRequired()])
    groups_data = HiddenField('Группы')
    create_mailbox = BooleanField('Создать почтовый ящик в Exchange', default=True)
    submit = SubmitField('Создать пользователя в AD')

