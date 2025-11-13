from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from repositories.user_repository import UserRepository
from models import User, UserCredentials

class UserService:
    def __init__(self):
        self.user_repository = UserRepository()

    def register_user(self, username, email, password, role):
        if self.user_repository.get_by_email(email):
            raise ValueError("Esta dirección de correo ya ha sido utilizada")

        new_user = User(username=username, email=email, is_active=True)
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        credentials = UserCredentials(password_hash=password_hash, role=role)

        self.user_repository.create_user_with_credentials(new_user, credentials)

        return self._generate_tokens(new_user, role)

    def authenticate(self, email, password):
        user = self.user_repository.get_by_email(email)
        if not user or not user.credential:
            return None 

        if not check_password_hash(user.credential.password_hash, password):
            return None 

        return self._generate_tokens(user, user.credential.role)

    def _generate_tokens(self, user, role):
        additional_claims = {
            'email': user.email,
            'role': role,
            'username': user.username
        }
        identity = str(user.id)
        
        access_token = create_access_token(identity=identity, additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=identity)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    
    def get_all_users(self):
        return self.user_repository.get_all_with_credentials()

    def get_user_detail(self, target_user_id, requester_id, requester_role):
        if requester_role != 'admin' and target_user_id != requester_id:
            raise PermissionError("Acceso denegado: permisos insuficientes")
        
        return self.user_repository.get_by_id_or_404(target_user_id)

    def update_user_role(self, user_id, new_role):
        user = self.user_repository.get_by_id_or_404(user_id)
        
        if user.credential:
            user.credential.role = new_role
            self.user_repository.update()
        return user

    def update_user_status(self, user_id, is_active):
        user = self.user_repository.get_by_id_or_404(user_id)
        user.is_active = is_active
        self.user_repository.update()
        return user

    def delete_user(self, user_id):
        user = self.user_repository.get_by_id_or_404(user_id)
        user.is_active = False
        self.user_repository.update()