from flask.views import MethodView
from flask import request, jsonify
from marshmallow import ValidationError
from werkzeug.security import generate_password_hash

from schemas import UserSchema, RegisterSchema, PostSchema
from models import User, UserCredentials, Post
from app import db


class UserAPI(MethodView):
    def get(self):
        users = User.query.all()
        return UserSchema(many=True).dump(users), 200
    
class UserRegisterAPI(MethodView):
    def post(self):
        try:
            data = RegisterSchema().load(request.json)
        except ValidationError as err:
            return {'errors': err.messages}, 400

        if User.query.filter_by(username=data['username']).first():
            return {'message': 'Este nombre de usuario ya ha sido utilizado'}, 400
        if User.query.filter_by(email=data['email']).first():
            return {'message': 'Esta direccion de correo ya ha sido utilizada'}, 400

        new_user = User(
            username=data['username'],
            email=data['email'],
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()

        password = data.get('password')
        password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
        )

        new_credentials = UserCredentials(
            user_id=new_user.id,
            password_hash=password_hash
        )
        db.session.add(new_credentials)
        db.session.commit()
        return UserSchema().dump(new_user)


class PostAPI(MethodView):
    def get(self, post_id):
        post = Post.query.get_or_404(post_id)
        return PostSchema().dump(post), 200