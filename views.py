from services.post_service import PostService
from services.comment_service import CommentService
from services.user_service import UserService

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
from sqlalchemy.orm import joinedload, subqueryload
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
    def __init__(self):
        self.user_service = UserService()

    def post(self):
        try:
            data = RegisterSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        try:
            tokens = self.user_service.register_user(
                username=data['username'],
                email=data['email'],
                password=data['password'],
                role=data['role']
            )
            return jsonify(tokens), 201
            
        except ValueError as e:
            return {'message': str(e)}, 400

class LoginAPI(MethodView):
    def __init__(self):
        self.user_service = UserService()

    @limiter.limit('10 per hour')
    def post(self):
        try:
            data = LoginSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        tokens = self.user_service.authenticate(data['email'], data['password'])

        if not tokens:
            return {'message': 'Credenciales inválidas'}, 401

        return jsonify(tokens), 200
    
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
    def __init__(self):
        self.post_service = PostService()

    def get(self):
        posts = self.post_service.get_all_posts()
        return PostSchema(many=True).dump(posts), 200

    @jwt_required()
    def post(self):
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
            
        user_id = get_user_identity_from_jwt()

        new_post = self.post_service.create_post(
            title=data['title'],
            content=data['content'],
            user_id=user_id,
            category_ids=data.get('categories', [])
        )
        
        return PostSchema().dump(new_post), 201
    
class PostDetailAPI(MethodView):
    def __init__(self):
        self.post_service = PostService()

    def get(self, post_id):
        post = self.post_service.get_post(post_id)
        return PostSchema().dump(post), 200

    @jwt_required()
    def put(self, post_id):
        user_id = get_user_identity_from_jwt()
        claims = get_jwt()
        role = claims.get('role')

        try:
            data = PostSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        try:
            updated_post = self.post_service.update_post(post_id, data, user_id, role)
            
            if updated_post is None: 
                 return {'error': 'Post no encontrado'}, 404
                 
            return PostSchema().dump(updated_post), 200

        except PermissionError as e:
            return {'error': str(e)}, 403
        except Exception as e:
            return {'error': 'Error interno al actualizar'}, 500

    @jwt_required()
    def delete(self, post_id):
        post = self.post_service.get_post(post_id) 
        if not is_admin_or_owner(post.user_id):
            return jsonify(error="No tienes permiso para eliminar este post"), 403

        self.post_service.delete_post(post_id)
        
        return jsonify(message="Post eliminado correctamente"), 200

    
class CommentAPI(MethodView):
    def __init__(self):
        self.comment_service = CommentService()

    @jwt_required()
    def put(self, comment_id):
        try:
            data = CommentSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        if 'content' not in data:
            return {'errors': 'El contenido es requerido'}, 400
            
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')

        try:
            updated_comment = self.comment_service.update_comment(
                comment_id=comment_id,
                new_content=data['content'],
                user_id=user_id,
                role=role
            )
            return CommentSchema().dump(updated_comment), 200
        except PermissionError as e:
            return {'error': str(e)}, 403

    @jwt_required()
    def delete(self, comment_id):
        user_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')

        try:
            self.comment_service.delete_comment(comment_id, user_id, role)
            return {'message': 'Comentario eliminado'}, 200
        except PermissionError as e:
            return {'error': str(e)}, 403


class CommentListAPI(MethodView):
    def __init__(self):
        self.comment_service = CommentService()

    def get(self, post_id):
        visible_comments = self.comment_service.get_post_comments(post_id)
        return CommentSchema(many=True).dump(visible_comments), 200
    
    @jwt_required()
    @limiter.limit('30 per hour', key_func=get_user_identity_from_jwt)
    def post(self, post_id):
        user_id = int(get_jwt_identity())

        try:
            data = CommentSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        try:
            new_comment = self.comment_service.create_comment(
                content=data['content'],
                post_id=post_id,
                user_id=user_id
            )
            return CommentSchema().dump(new_comment), 201
        except Exception as e:
            return {'error': 'Error al crear el comentario'}, 400
          
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

        return CategorySchema().dump(new_category), 201
    

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
    def __init__(self):
        self.user_service = UserService()

    @jwt_required()
    @role_required('admin')
    def get(self):
        users = self.user_service.get_all_users()
        return UserSchema(many=True).dump(users), 200

class UserDetailAPI(MethodView):
    def __init__(self):
        self.user_service = UserService()

    @jwt_required()
    def get(self, user_id):
        requester_id = int(get_jwt_identity())
        claims = get_jwt()
        role = claims.get('role')

        try:
            user = self.user_service.get_user_detail(user_id, requester_id, role)
            return UserSchema().dump(user), 200
        except PermissionError as e:
            return {'error': str(e)}, 403
       
    @jwt_required()
    @role_required('admin')
    def delete(self, user_id):
        self.user_service.delete_user(user_id)
        return {'message': 'Usuario desactivado'}, 200

class UserRoleAPI(MethodView):
    def __init__(self):
        self.user_service = UserService()

    @jwt_required()
    @role_required('admin')
    def patch(self, user_id):
        try:
            data = RoleUpdateSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        self.user_service.update_user_role(user_id, data['role'])
        return {'message': 'Rol de usuario actualizado'}, 200

class UserStatusAPI(MethodView):
    def __init__(self):
        self.user_service = UserService()

    @jwt_required()
    @role_required('admin')
    def patch(self, user_id):
        try:
            data = UserSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        self.user_service.update_user_status(user_id, data['is_active'])
        return jsonify({'message': 'Estado de usuario actualizado'}), 200


class StatsAPI(MethodView):
    @jwt_required()
    @role_required('admin', 'moderator')
    def get(self):
        total_posts = Post.query.filter_by(is_published=True).count()
        total_comments = Comment.query.filter_by(is_visible=True).count()
        total_users = User.query.filter_by(is_active=True).count()
        post_last_week = Post.query.filter(
            Post.date_created >= db.func.now() - db.text('INTERVAL 7 DAY'),
            Post.is_published == True
        ).count()

        stats = {
            'total_posts': total_posts,
            'total_comments': total_comments,
            'total_users': total_users,
            'posts_last_week': post_last_week
        }
        return jsonify(stats), 200