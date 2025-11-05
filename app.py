from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql+pymysql://root:@localhost/EFI'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'clave-ultra-secreta'

from models import db
from views import UserRegisterAPI, PostAPI, LoginAPI, PostDetailAPI, CategoryAPI, CategoryDetailAPI, CommentListAPI, CommentAPI, UserAPI, UserDetailAPI, UserRoleAPI, StatsAPI

jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)


app.add_url_rule(
    '/register',
    view_func=UserRegisterAPI.as_view('register_api'), 
    methods=['POST']
)

app.add_url_rule(
    '/login',
    view_func=LoginAPI.as_view('login_api'),
    methods=['POST']
)

app.add_url_rule(
    '/post',
    view_func=PostAPI.as_view('post_api'), 

)

app.add_url_rule(
    '/post/<int:post_id>',
    view_func=PostDetailAPI.as_view('post_detail_api'),
    methods=['GET', 'PUT', 'DELETE']
)

app.add_url_rule(
    '/post/<int:post_id>/comments',
    view_func=CommentListAPI.as_view('post_comment_api'),
    methods=['POST', 'GET']
)

app.add_url_rule(
    '/comments/<int:comment_id>',
    view_func=CommentAPI.as_view('comment_api'),
    methods=['DELETE']  
)

app.add_url_rule(
    '/category',
    view_func=CategoryAPI.as_view('category_api'),
    methods=['POST', 'GET']
)

app.add_url_rule(
    '/category/<int:category_id>',
    view_func=CategoryDetailAPI.as_view('category_detail_api'),
    methods=['PUT', 'DELETE']
)

app.add_url_rule(
    '/users',
    view_func=UserAPI.as_view('user_api'),
    methods=['GET']
)

app.add_url_rule(
    '/users/<int:user_id>',
    view_func=UserDetailAPI.as_view('user_detail_api'),
    methods=['GET', 'DELETE']
)

app.add_url_rule(
    '/users/<int:user_id>/role',
    view_func=UserRoleAPI.as_view('user_role_api'),
    methods=['PATCH']
)

app.add_url_rule(
    '/stats',
    view_func=StatsAPI.as_view('stats_api'),
    methods=['GET']
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