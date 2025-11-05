from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate


from models import db
from views import UserRegisterAPI, PostAPI, LoginAPI, CategoryAPI, CommentListAPI, PostDetailAPI

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mysql+pymysql://root:@localhost/EFI'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'clave-ultra-secreta'

jwt = JWTManager(app)
db.init_app(app)
migrate = Migrate(app, db)


# Rutas Nuevas

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
    methods=['GET', 'POST']
)

app.add_url_rule(
    '/post/<int:post_id>',
    view_func=PostDetailAPI.as_view('post_detail_api'),
    methods=['GET', 'PATCH', 'PUT', 'DELETE']
)

app.add_url_rule(
    '/post/<int:post_id>/comment',
    view_func=CommentListAPI.as_view('post_comment_api'),
    methods=['POST']
)

app.add_url_rule(
    '/category',
    view_func=CategoryAPI.as_view('category_api'),
    methods=['POST', 'GET']
)

# Rutas Viejas

@app.route('/')
def index():
    return jsonify({
        "api_name": "MiniBlog API",
        "status": "ok",
        "version": "1.0.0"
    }), 200



if __name__ == '__main__':
    app.run(debug=True)