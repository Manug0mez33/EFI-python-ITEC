from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


post_categories = db.Table(
    'post_categories',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.id'), primary_key=True)
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def str(self):
        return self.username


class UserCredentials(db.Model):
    __tablename__ = 'user_credentials'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50),nullable=False ,default='user')
    user = db.relationship(
        'User', 
        backref=db.backref('credential', uselist=False)
    )

    def __str__(self) -> str:
        return f'User Credentials for user id ={self.user_id}, role={self.role}'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, server_default=db.func.now())                                     
    is_published = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(
        'User',
        backref='posts',
        lazy=True
    )
    categories = db.relationship(
        'Category',
        secondary=post_categories,
        backref=db.backref('posts', lazy='dynamic')
    )

    def str(self):
        return self.title


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, server_default=db.func.now())
    is_visible = db.Column(db.Boolean, default=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post = db.relationship(
        'Post',
        backref='comments',
        lazy=True
    )
    user = db.relationship(
        'User',
        backref='comments',
        lazy=True
    )


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __str__(self):
        return self.name