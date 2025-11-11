from datetime import timedelta
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

app = Flask(__name__)

CORS(app,
     origins=['http://localhost:5173'],
     supports_credentials=True
     )

app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql+pymysql://root:@localhost/EFI'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'clave-ultra-secreta'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=24)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

from models import db
from views import (
    UserRegisterAPI, 
    PostAPI, 
    LoginAPI, 
    PostDetailAPI, 
    CategoryAPI, 
    CategoryDetailAPI, 
    CommentListAPI, 
    CommentAPI, 
    UserAPI, 
    UserDetailAPI, 
    UserRoleAPI,
    UserStatusAPI, 
    StatsAPI, 
    RefreshAPI
)

jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)

app.add_url_rule(
    '/refresh',
    view_func=RefreshAPI.as_view('refresh_api')
)

app.add_url_rule(
    '/register',
    view_func=UserRegisterAPI.as_view('register_api')
)

app.add_url_rule(
    '/login',
    view_func=LoginAPI.as_view('login_api')
)

app.add_url_rule(
    '/post',
    view_func=PostAPI.as_view('post_api')
)

app.add_url_rule(
    '/post/<int:post_id>',
    view_func=PostDetailAPI.as_view('post_detail_api')
)

app.add_url_rule(
    '/post/<int:post_id>/comments',
    view_func=CommentListAPI.as_view('post_comment_api')
)

app.add_url_rule(
    '/comments/<int:comment_id>',
    view_func=CommentAPI.as_view('comment_api')
)

app.add_url_rule(
    '/category',
    view_func=CategoryAPI.as_view('category_api')
)

app.add_url_rule(
    '/category/<int:category_id>',
    view_func=CategoryDetailAPI.as_view('category_detail_api')
)

app.add_url_rule(
    '/users',
    view_func=UserAPI.as_view('user_api')
)

app.add_url_rule(
    '/users/<int:user_id>',
    view_func=UserDetailAPI.as_view('user_detail_api')
)

app.add_url_rule(
    '/users/<int:user_id>/role',
    view_func=UserRoleAPI.as_view('user_role_api')
)

app.add_url_rule (
    '/users/<int:user_id>/status',
    view_func=UserStatusAPI.as_view('user_status_api')
)

app.add_url_rule(
    '/stats',
    view_func=StatsAPI.as_view('stats_api')
)

@app.route('/')
def index():
    return jsonify({
        "api_name": "MiniBlog API",
        "status": "ok",
        "version": "1.0.0"
    }), 200

@app.cli.command("seed-db")
def seed_db():
    """Crea datos de prueba en la base de datos (1 usuario por rol)."""
    from models import User, UserCredentials
    from werkzeug.security import generate_password_hash

    test_users = [
        {
            "username": "admin",
            "email": "admin@admin",
            "password": "1234",
            "role": "admin"
        },
        {
            "username": "moderator",
            "email": "moderator@moderator",
            "password": "1234",
            "role": "moderator"
        },
        {
            "username": "user",
            "email": "user@user",
            "password": "1234",
            "role": "user"
        }
    ]

    print("Creando usuarios de prueba...")
    for user_data in test_users:
        user = User.query.filter_by(email=user_data["email"]).first()
        if user:
            print(f"El usuario {user_data['email']} ya existe.")
            continue

        new_user = User(
            username=user_data['username'],
            email=user_data['email'],
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()

        password_hash = generate_password_hash(user_data['password'], method='pbkdf2:sha256')
        credentials = UserCredentials(user_id=new_user.id, password_hash=password_hash, role=user_data['role'])
        db.session.add(credentials)
        print(f"Usuario {user_data['username']} ({user_data['role']}) creado.")
    
    db.session.commit()
    print("Datos de prueba creados con exito.")


if __name__ == '__main__':
    app.run(debug=True)