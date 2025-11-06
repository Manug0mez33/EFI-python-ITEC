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
from typing import Any, Dict
from schemas import UserSchema, RegisterSchema, LoginSchema, PostSchema, CommentSchema, CategorySchema, RoleUpdateSchema
from models import User, UserCredentials, Post, Comment, Category
from app import db, limiter
from services.post_service import PostService
from services.user_service import UserService
from services.comment_service import CommentService
from services.category_service import CategoryService
from services.stats_service import StatsService

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
        self.service = UserService()

    def post(self):
        try:
            data = RegisterSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        result, status_code = self.service.register_user(data)
        return result, status_code

class LoginAPI(MethodView):
    def __init__(self):
        self.service = UserService()

    @limiter.limit('10 per hour')
    def post(self):
        try:
            data = LoginSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        result, status_code = self.service.login_user(data)
        if status_code == 200:
            return jsonify(result)
        return result, status_code
    
class RefreshAPI(MethodView):
    def __init__(self):
        self.service = UserService()

    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        result, status_code = self.service.refresh_token(identity)
        if status_code == 200:
            return jsonify(result)
        return result, status_code

class PostAPI(MethodView):
    def __init__(self):
        self.service = PostService()

    def get(self):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        author_username = request.args.get('author_username', type=str)
        category_name = request.args.get('category_name', type=str)
        
        result = self.service.get_all_posts(page, per_page, author_username, category_name)
        return jsonify(result), 200

    @limiter.limit('10 per hour', key_func=get_user_identity_from_jwt)
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        new_post = self.service.create_post(data['title'], data['content'], int(current_user))
        return new_post, 201
    
class PostDetailAPI(MethodView):
    def __init__(self):
        self.service = PostService()

    def get(self, post_id):
        post = self.service.get_post_by_id(post_id)
        return post, 200
    
    @jwt_required()
    def delete(self, post_id):
        post = self.service.get_post_by_id(post_id)
        if not is_admin_or_owner(post['user_id']):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        self.service.delete_post(post_id)
        return {'message': 'Post deleted'}, 200
    
    @jwt_required()
    def put(self, post_id):
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        post = self.service.get_post_by_id(post_id)
        if not is_admin_or_owner(post['user_id']):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        
        updated_post = self.service.update_post(post_id, data['title'], data['content'])
        return updated_post, 200

    
class CommentAPI(MethodView):
    def __init__(self):
        self.service = CommentService()

    @jwt_required()
    def delete(self, comment_id):
        comment = self.service.comment_repository.get_by_id(comment_id)
        claims = get_jwt()
        current_user_role = claims.get('role')

        if (not is_admin_or_owner(comment.user_id)) and (current_user_role != 'moderator'):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        else:
            self.service.delete_comment(comment_id)
            return {'message': 'Comment deleted'}, 200

class CommentListAPI(MethodView):
    def __init__(self):
        self.service = CommentService()
        self.post_service = PostService()

    def get(self, post_id):
        #This should be handled by the post service
        self.post_service.get_post_by_id(post_id)
        comments = self.service.get_comments_by_post(post_id)
        return comments, 200
    
    @limiter.limit('30 per hour', key_func=get_user_identity_from_jwt)
    @jwt_required()
    def post(self, post_id):
        self.post_service.get_post_by_id(post_id)
        current_user = get_jwt_identity()

        try:
            data = CommentSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        new_comment = self.service.create_comment(
            content=data['content'],
            post_id=post_id,
            user_id=int(current_user)
        )
        return new_comment, 201
    
class CategoryAPI(MethodView):
    def __init__(self):
        self.service = CategoryService()

    def get(self):
        categories = self.service.get_all_categories()
        return categories, 200
    
    @jwt_required()
    @role_required('admin', 'moderator')
    def post(self):
        try:
            data = CategorySchema().load(request.json)
        except ValidationError as err:
            return jsonify({'success': False, 'errors': err.messages}), 400
        
        result, status_code = self.service.create_category(data['name'])
        return result, status_code

class CategoryDetailAPI(MethodView):
    def __init__(self):
        self.service = CategoryService()

    @jwt_required()
    @role_required('admin', 'moderator')
    def put(self, category_id):
        try:
            data = CategorySchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        updated_category = self.service.update_category(category_id, data['name'])
        return updated_category, 200
    
    @jwt_required()
    @role_required('admin')
    def delete(self, category_id):
        self.service.delete_category(category_id)
        return {'message': 'Category deleted'}, 200
    
class UserAPI(MethodView):
    def __init__(self):
        self.service = UserService()

    @jwt_required()
    @role_required('admin')
    def get(self):
        users = self.service.get_all_users()
        return users, 200
    
class UserDetailAPI(MethodView):
    def __init__(self):
        self.service = UserService()

    @jwt_required()
    def get(self, user_id):
        if not is_admin_or_owner(user_id):
            return {'error': 'Acceso denegado: permisos insuficientes'}, 403
        user = self.service.get_user_by_id(user_id)
        return user, 200
       

    @jwt_required()
    @role_required('admin')
    def delete(self, user_id):
        self.service.deactivate_user(user_id)
        return {'message': 'Usuario desactivado'}, 200
    
class UserRoleAPI(MethodView):
    def __init__(self):
        self.service = UserService()

    @jwt_required()
    @role_required('admin')
    def patch(self, user_id):
        try:
            data = RoleUpdateSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        result, status_code = self.service.update_user_role(user_id, data['role'])
        return result, status_code
    
class StatsAPI(MethodView):
    def __init__(self):
        self.service = StatsService()

    @jwt_required()
    @role_required('admin', 'moderator')
    def get(self):
        stats = self.service.get_stats()
        return jsonify(stats), 200