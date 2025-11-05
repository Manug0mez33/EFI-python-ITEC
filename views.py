from datetime import timedelta
from flask.views import MethodView
from flask import request, jsonify
from marshmallow import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    get_jwt,
    get_jwt_identity
)
from flask_login import current_user

from schemas import UserSchema, RegisterSchema, LoginSchema, PostSchema, CommentSchema, CategorySchema
from models import User, UserCredentials, Post, Comment, Category
from app import db

    
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
        return UserSchema().dump(new_user)

class LoginAPI(MethodView):
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
        token = create_access_token(
            identity=identity,
            additional_claims=additional_claims,
            expires_delta=timedelta(minutes=5)
        )

        return jsonify(access_token=token)
    
class PostAPI(MethodView):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        return PostSchema().dump(post), 200
    
    def post(self):
        if not current_user.is_authenticated:
            return {'message': 'Authentication required'}, 401 

        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        new_post = Post(
            title=data['title'],
            content=data['content'],
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return PostSchema().dump(new_post), 201
    

class PostDetailAPI(MethodView):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        return PostSchema().dump(post), 200
    
    def delete(self, post_id):
        post = Post.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()
        return {'message': 'Post deleted'}, 200
    
    def put(self, post_id):
        post = Post.query.get_or_404(post_id)
        try:
            data = PostSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        post.title = data['title']
        post.content = data['content']
        db.session.commit()
        return PostSchema().dump(post), 200
    
    def patch(self, post_id):
        post = Post.query.get_or_404(post_id)
        try:
            data = PostSchema(partial=True).load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        if 'title' in data:
            post.title = data['title']
        if 'content' in data:
            post.content = data['content']
        db.session.commit()
        return PostSchema().dump(post), 200
    

class CommentListAPI(MethodView):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        return CommentSchema(many=True).dump(post.comments), 200
    
    def post(self, post_id):
        if not current_user.is_authenticated:
            return {'message': 'Authentication required'}, 401

        Post.query.get_or_404(post_id)
        try:
            data = CommentSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        new_comment = Comment(
            content=data['content'],
            post_id=post_id,
            user_id=current_user.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return CommentSchema().dump(new_comment), 201
    

class CategoryAPI(MethodView):
    def get(self):
        categories = Category.query.all()
        return CategorySchema(many=True).dump(categories), 200
    
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
                'id': data['id'],
                'name': data['name']
            }
        })