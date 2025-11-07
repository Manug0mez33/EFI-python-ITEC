from datetime import timedelta
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger

app = Flask(__name__)

swagger = Swagger(app)

from schemas import UserSchema, RegisterSchema, LoginSchema, PostSchema, CommentSchema, CategorySchema, RoleUpdateSchema, NotificationSchema

app.config['SWAGGER'] = {
    'title': 'API de MiniBlog',
    'uiversion': 2,
    'specs': [
        {
            'endpoint': 'apispec_1',
            'route': '/apispec_1.json',
            'rule_filter': lambda rule: True,
            'model_filter': lambda tag: True,
        }
    ],
    'definitions': {
        'Register': RegisterSchema,
        'Login': LoginSchema,
        'Post': PostSchema,
        'Comment': CommentSchema,
        'Category': CategorySchema,
        'RoleUpdate': RoleUpdateSchema,
        'Notification': NotificationSchema,
        'User': UserSchema
    }
}


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
    StatsAPI, 
    RefreshAPI,
    NotificationAPI,
    NotificationReadAPI
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
    '/notifications',
    view_func=NotificationAPI.as_view('notification_api')
)

app.add_url_rule(
    '/notifications/<int:notification_id>/read',
    view_func=NotificationReadAPI.as_view('notification_read_api')
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


if __name__ == '__main__':
    app.run(debug=True)