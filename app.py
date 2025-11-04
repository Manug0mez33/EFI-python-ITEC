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
from schemas import UserSchema

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

@app.route('/')
def index():
    return render_template(
        'index.html'
    )

@app.route('/post', methods=['GET', 'POST'])
def post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_ids = request.form.getlist('categories')
        categories = Category.query.filter(Category.id.in_(category_ids)).all()
        
        new_post = Post(
            title=title,
            content=content,
            user_id=current_user.id,
            categories=categories
        )
        
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully.', 'success')
        return redirect(url_for('post'))
    
    posts = Post.query.order_by(Post.date_created.desc()).all()
    return render_template(
        "post.html",
        posts=posts
    )

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    data = request.get_json()
    category_name = data.get('name')

    if not category_name:
        return jsonify({'success': False, 'message': 'El nombre de la categoría no puede estar vacío.'}), 400
    
    if Category.query.filter_by(name=category_name).first():
        return jsonify({'success': False, 'message': 'Esa categoría ya existe.'}), 400

    new_category = Category(name=category_name)
    db.session.add(new_category)
    db.session.commit()

    return jsonify({
        'success': True,
        'category': {
            'id': new_category.id,
            'name': new_category.name
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = UserSchema().load(request.json)
            
            password = data.get('password')

            password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            )

            new_user = User(username=data['username'],
                            email=data['email'],
                            password_hash=password_hash,
                            is_active=data.get('is_active', True)
                            )
            
            user = User.query.filter_by(username=data.get('username')).first()
            if user:
                return jsonify({'success': False, 'message': 'Username already exists.'}), 400
            mail = User.query.filter_by(email=data.get('email')).first()
            if mail:
                return jsonify({'success': False, 'message': 'Email already registered.'}), 400
            
            db.session.add(new_user)
            db.session.commit()
            jsonify({'success': True, 'message': 'User registered successfully.'}), 201
        except ValidationError as err:
            return {"Errors": f"{err.messages}"}, 400
        
        
        
        
        flash('Registration successful. Please log in.', 'success')
        return UserSchema().dump(new_user)
        

    return render_template(
        'auth/register.html'
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form['content']

        new_comment = Comment(
            content=content, 
            post_id=post.id, 
            user_id=current_user.id
        )

        db.session.add(new_comment)
        db.session.commit()
        flash('Comentario agregado.', 'success')
        return redirect(url_for('post_detail', post_id=post.id))
    
    return render_template(
        'post_detail.html', 
        post=post
    )

@app.route('/users', methods=['GET', 'POST'])
def users():
    if request.method == 'POST':
        data = request.json
        print(data)
    users = User.query.all()
    return UserSchema(many=True).dump(users)


if __name__ == '__main__':
    app.run(debug=True)