import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_required
from werkzeug.utils import secure_filename

from utils import admin_required
from forms import ArticleForm
from models import db, Article, Category, ArticleImage

articles_bp = Blueprint('articles', __name__, url_prefix='/articles')

@articles_bp.route('/')
@login_required
def index():
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

@articles_bp.route('/new', methods=['GET', 'POST'])
@admin_required
def new():
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
                    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
                    db.session.add(ArticleImage(filename=filename, article_id=article.id))
        db.session.commit()
        flash('Статья добавлена', 'success')
        return redirect(url_for('articles.index'))
    return render_template('article_form.html', form=form)

@articles_bp.route('/<int:article_id>')
@login_required
def view(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template('article_view.html', article=article)

@articles_bp.route('/<int:article_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit(article_id):
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
                    img_path = os.path.join(current_app.config['UPLOAD_FOLDER'], img.filename)
                    if os.path.exists(img_path):
                        os.remove(img_path)
                    db.session.delete(img)
        if form.images.data:
            for file in form.images.data:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
                    db.session.add(ArticleImage(filename=filename, article_id=article.id))
        db.session.commit()
        flash('Статья обновлена', 'success')
        return redirect(url_for('articles.view', article_id=article.id))
    return render_template('article_form.html', form=form, edit=True, article=article)

@articles_bp.route('/<int:article_id>/delete')
@admin_required
def delete(article_id):
    article = Article.query.get_or_404(article_id)
    for img in article.images:
        image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], img.filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(article)
    db.session.commit()
    flash('Статья удалена', 'success')
    return redirect(url_for('articles.index'))

@articles_bp.route('/image/<int:image_id>/delete', methods=['POST'])
@admin_required
def delete_image(image_id):
    image = ArticleImage.query.get_or_404(image_id)
    image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], image.filename)
    if os.path.exists(image_path):
        os.remove(image_path)
    db.session.delete(image)
    db.session.commit()
    return jsonify({'success': True})
