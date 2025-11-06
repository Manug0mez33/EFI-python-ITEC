from models import db, User, UserCredentials
from werkzeug.security import generate_password_hash

class UserRepository:
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def get_by_id(user_id):
        return User.query.get_or_404(user_id)

    @staticmethod
    def get_all():
        return User.query.all()

    @staticmethod
    def create(username, email, password, role):
        new_user = User(
            username=username,
            email=email,
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        credentials = UserCredentials(
            user_id=new_user.id,
            password_hash=password_hash,
            role=role
        )
        db.session.add(credentials)
        db.session.commit()
        return new_user

    @staticmethod
    def deactivate(user):
        user.is_active = False
        db.session.commit()

    @staticmethod
    def update_role(user, role):
        user.credential.role = role
        db.session.commit()
