from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from marshmallow import ValidationError
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = 'clave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql+pymysql://root:@localhost/EFI'
)

from models import db, User, Post, Comment, Category
from schemas import UserSchema, PostSchema, CommentSchema, CategorySchema
from views import UserRegisterAPI, PostAPI

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.context_processor
def inject_categories():
    return dict(categories=Category.query.order_by(Category.name).all())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas Nuevas

app.add_url_rule(
    '/register',
    view_func=UserRegisterAPI.as_view('register_api'), 
    methods=['POST']
)

app.add_url_rule(
    '/post',
    view_func=PostAPI.as_view('post_api'), 
    methods=['GET', 'POST']
)

app.add_url_rule(
    '/post/<int:post_id>',
    view_func=PostAPI.as_view('post_detail_api'),
    methods=['GET', 'PATCH', 'PUT', 'DELETE']
)

app.add_url_rule(
    '/post/<int:post_id>/comment',
    view_func=PostAPI.as_view('post_comment_api'),
    methods=['POST']
)


# Rutas Viejas

@app.route('/')
def index():
    return render_template(
        'index.html'
    )

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    try:
        data = CategorySchema().load(request.json)
        category_name = data.get('name')
        
        if Category.query.filter_by(name=data.get('name')).first():
            return jsonify({'success': False, 'message': 'Esa categoría ya existe.'}), 400

        new_category = Category(name=data['name'])
        db.session.add(new_category)
        db.session.commit()

    except ValidationError as err:
        return jsonify({'success': False, 'errors': err.messages}), 400
    
    return jsonify({
        'success': True,
        'category': {
            'id': data['id'],
            'name': data['name']
        }
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(pwhash=user.password_hash, password=password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template(
        'auth/login.html'
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)