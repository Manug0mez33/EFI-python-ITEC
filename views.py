from datetime import timedelta
from flask.views import MethodView
from flask import request, jsonify
from marshmallow import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity
)
from flask_login import current_user

from functools import wraps
from schemas import UserSchema, RegisterSchema, LoginSchema, PostSchema, CommentSchema, CategorySchema, RoleUpdateSchema, NotificationSchema
from models import User, UserCredentials, Post, Comment, Category, Notification
from app import db, limiter

def get_user_identity_from_jwt():
    return int(get_jwt_identity())

def role_required(*allowed_roles: str):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get('role')
            if role not in allowed_roles:
                return {'error': 'Acceso denegado: permisos insuficientes'}, 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
    
def is_admin_or_owner(resource_owner_id: int) -> bool:
    claims = get_jwt()
    current_user_role = claims.get('role')
    if current_user_role == 'admin':
        return True
    
    user_id = int(get_jwt_identity())
    if user_id == resource_owner_id:
        return True
    return False

class UserRegisterAPI(MethodView):
    def post(self):
        try:
            data = RegisterSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'Esta direccion de correo ya ha sido utilizada'}, 400

        new_user = User(
            username=data['username'],
            email=data['email'],
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()

        password_hash = generate_password_hash(data['password'], method='pbkdf2:sha256')
        credentials = UserCredentials(
            user_id=new_user.id,
            password_hash=password_hash,
            role=data['role']
        )
        db.session.add(credentials)
        db.session.commit()
        return {'message': 'Usuario registrado exitosamente'}, 201

class LoginAPI(MethodView):
    @limiter.limit('10 per hour')
    def post(self):
        try:
            data = LoginSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        user = User.query.filter_by(email=data['email']).first()
        if not user or not user.credential:
            return {'message': 'Usuario no encontrado'}, 404

        if not check_password_hash(user.credential.password_hash, data['password']):
            return {'message': 'Credenciales inválidas'}, 401

        additional_claims = {
            'email': user.email,
            'role': user.credential.role,
            'username': user.username
            }

        identity = str(user.id)
        access_token = create_access_token(
            identity=identity,
            additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(identity=identity)

        return jsonify(access_token=access_token, refresh_token=refresh_token)
    
class RefreshAPI(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        user = User.query.get(int(identity))
        if not user or not user.is_active:
            return {'message': 'Usuario no encontrado o inactivo'}, 404
        
        additional_claims = {
            'email': user.email,
            'role': user.credential.role,
            'username': user.username
        }
    
        new_access_token = create_access_token(
            identity=identity,
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=24)
        )
        return jsonify(access_token=new_access_token)

class PostAPI(MethodView):
    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        author_username = request.args.get('author_username', type=str)
        category_name = request.args.get('category_name', type=str)

        query = Post.query.filter_by(is_published=True)

        if author_username:
            query = query.join(User).filter(User.username == author_username)

        if category_name:
            query = query.filter(Post.categories.any(name=category_name)) 

        query = query.order_by(Post.date_created.desc())

        paginated_posts = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        return jsonify({
            'posts': PostSchema(many=True).dump(paginated_posts.items),
            'pagination': {
                'total_pages': paginated_posts.pages,
                'total_items': paginated_posts.total,
                'current_page': paginated_posts.page,
                'per_page': paginated_posts.per_page,
                'has_next': paginated_posts.has_next,
                'has_prev': paginated_posts.has_prev
            }
        }), 200

    @jwt_required()
    @limiter.limit('10 per hour', key_func=get_user_identity_from_jwt)
    def post(self):
        current_user = get_jwt_identity()
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        new_post = Post(
            title=data['title'],
            content=data['content'],
            user_id=int(current_user)
        )
        db.session.add(new_post)
        db.session.commit()
        return PostSchema().dump(new_post), 201
    
class PostDetailAPI(MethodView):
    def get(self, post_id):
        post = Post.query.filter_by(post_id, is_published=True).first_or_404()
        return PostSchema().dump(post), 200
    
    @jwt_required()
    def delete(self, post_id):
        post = Post.query.get_or_404(post_id)
        if not is_admin_or_owner(post.user_id):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        post.is_published = False
        db.session.commit()
        return {'message': 'Post deleted'}, 200
    
    @jwt_required()
    def put(self, post_id):
        post = Post.query.get_or_404(post_id)
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        if not is_admin_or_owner(post.user_id):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        post.title = data['title']
        post.content = data['content']
        db.session.commit()
        return PostSchema().dump(post), 200

    
class CommentAPI(MethodView):
    @jwt_required()
    def delete(self, comment_id):
        comment = Comment.query.get_or_404(comment_id)
        claims = get_jwt()
        current_user_role = claims.get('role')

        if (not is_admin_or_owner(comment.user_id)) and (current_user_role != 'moderator'):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        else:
            comment.is_visible = False
            db.session.commit()
            return {'message': 'Comment deleted'}, 200

class CommentListAPI(MethodView):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        visible_comments = post.comments.filter_by(is_visible=True)
        return CommentSchema(many=True).dump(visible_comments), 200
    
    @jwt_required()
    @limiter.limit('30 per hour', key_func=get_user_identity_from_jwt)
    def post(self, post_id):
        post = Post.query.get_or_404(post_id)
        current_user = int(get_jwt_identity())

        try:
            data = CommentSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        new_comment = Comment(
            content=data['content'],
            post_id=post.id,
            user_id=current_user
        )
        db.session.add(new_comment)
        db.session.commit()

        if post.user_id != current_user:
            actor = User.query.get(current_user)
            notification = Notification(
                user_id=post.user_id,
                actor_id=current_user,
                post_id=post.id,
                message=f'{actor.username} ha comentado en tu publicación.'
            )
            db.session.add(notification)
            db.session.commit()

        return CommentSchema().dump(new_comment), 201
    
class NotificationAPI(MethodView):
    @jwt_required()
    def get(self):
        user_id = int(get_jwt_identity())
        notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.time.desc()).all()
        return NotificationSchema(many=True).dump(notifications), 200
    
class NotificationReadAPI(MethodView):
    @jwt_required()
    def patch(self, notification_id):
        user_id = int(get_jwt_identity())
        notification = Notification.query.get_or_404(notification_id)

        if notification.user_id != user_id:
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        
        notification.is_read = True
        db.session.commit()
        return {'message': 'Notification read'}, 200
        
class CategoryAPI(MethodView):
    def get(self):
        categories = Category.query.filter_by(is_visible=True).all()
        return CategorySchema(many=True).dump(categories), 200
    
    @jwt_required()
    @role_required('admin', 'moderator')
    def post(self):
        try:
            data = CategorySchema().load(request.json)
        except ValidationError as err:
            return jsonify({'success': False, 'errors': err.messages}), 400
        
        if Category.query.filter_by(name=data.get('name')).first():
            return jsonify({'success': False, 'message': 'Esa categoría ya existe.'}), 400
        
        new_category = Category(name=data['name'])
        db.session.add(new_category)
        db.session.commit()

        return jsonify({
            'success': True,
            'category': {
                'name': data['name']
            }
        })

class CategoryDetailAPI(MethodView):
    @jwt_required()
    @role_required('admin', 'moderator')
    def put(self, category_id):
        category = Category.query.get_or_404(category_id)
        try:
            data = CategorySchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        category.name = data['name']
        db.session.commit()
        return {'message': 'Category updated'}, 200
    
    @jwt_required()
    @role_required('admin')
    def delete(self, category_id):
        category = Category.query.get_or_404(category_id)
        category.is_visible = False
        db.session.commit()
        return {'message': 'Category deleted'}, 200
    
class UserAPI(MethodView):
    @jwt_required()
    @role_required('admin')
    def get(self):
        users = User.query.filter_by(is_active=True).all()
        return UserSchema(many=True).dump(users), 200
    
class UserDetailAPI(MethodView):
    @jwt_required()
    def get(self, user_id):
        if not is_admin_or_owner(user_id):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        user = User.query.get_or_404(user_id)
        return UserSchema().dump(user), 200
       
    @jwt_required()
    @role_required('admin')
    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        user.is_active = False
        db.session.commit()
        return {'message': 'Usuario desactivado'}, 200
    
class UserRoleAPI(MethodView):
    @jwt_required()
    @role_required('admin')
    def patch(self, user_id):
        try:
            data = RoleUpdateSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        user = User.query.get_or_404(user_id)
        user.credential.role = data['role']
        db.session.commit()
        return {'message': 'Rol de usuario actualizado'}, 200
    
class StatsAPI(MethodView):
    @jwt_required()
    @role_required('admin', 'moderator')
    def get(self):
        total_posts = Post.query.count()
        total_comments = Comment.query.count()
        total_users = User.query.count()
        post_last_week = Post.query.filter(
            Post.date_created >= db.func.now() - db.text('INTERVAL 7 DAY')
        ).count()

        stats = {
            'total_posts': total_posts,
            'total_comments': total_comments,
            'total_users': total_users,
            'posts_last_week': post_last_week
        }
        return jsonify(stats), 200