from repositories.user_repository import UserRepository
from schemas import UserSchema
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from datetime import timedelta

class UserService:
    def __init__(self):
        self.user_repository = UserRepository()

    def register_user(self, data):
        if self.user_repository.get_by_email(data['email']):
            return {'message': 'Esta direccion de correo ya ha sido utilizada'}, 400

        self.user_repository.create(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            role=data['role']
        )
        return {'message': 'Usuario registrado exitosamente'}, 201

    def login_user(self, data):
        user = self.user_repository.get_by_email(data['email'])
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

        return {'access_token': access_token, 'refresh_token': refresh_token}, 200

    def get_all_users(self):
        users = self.user_repository.get_all()
        return UserSchema(many=True).dump(users)

    def get_user_by_id(self, user_id):
        user = self.user_repository.get_by_id(user_id)
        return UserSchema().dump(user)

    def deactivate_user(self, user_id):
        user = self.user_repository.get_by_id(user_id)
        self.user_repository.deactivate(user)
        return {'message': 'Usuario desactivado'}, 200

    def update_user_role(self, user_id, role):
        user = self.user_repository.get_by_id(user_id)
        self.user_repository.update_role(user, role)
        return {'message': 'Rol de usuario actualizado'}, 200
    
    def refresh_token(self, identity):
        user = self.user_repository.get_by_id(int(identity))
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
        return {'access_token': new_access_token}, 200
