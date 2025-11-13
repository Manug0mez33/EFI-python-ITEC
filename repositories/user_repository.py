from sqlalchemy.orm import joinedload
from app import db
from models import User, UserCredentials

class UserRepository:
    def get_by_id(self, user_id):
        return User.query.get(user_id)

    def get_by_email(self, email):
        return User.query.filter_by(email=email).first()

    def create_user_with_credentials(self, user, credentials):
        db.session.add(user)
        db.session.flush() 
        
        credentials.user_id = user.id
        db.session.add(credentials)
        
        db.session.commit()
        return user

    def update(self):
        db.session.commit()

    def get_by_id_or_404(self, user_id):
        return User.query.get_or_404(user_id)

    def get_all_with_credentials(self):
        return User.query.options(joinedload(User.credential)).all()

    def update(self):
        db.session.commit()