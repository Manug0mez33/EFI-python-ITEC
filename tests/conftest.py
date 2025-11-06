import pytest
from app import create_app
from models import db as main_db
from models import User, UserCredentials, Post, Comment, Category, post_categories
from werkzeug.security import generate_password_hash
from flask_jwt_extended import JWTManager

@pytest.fixture(scope='session')
def app():
    """Configura la app de Flask para pruebas."""
    # Llama a la fábrica con la config de 'testing'
    app = create_app('testing')
    
    # Initialize JWTManager for the test app
    JWTManager(app)
    
    yield app

@pytest.fixture(scope='session')
def db(app):
    """Configura la base de datos para pruebas."""
    with app.app_context():
        main_db.create_all()  # Crea todas las tablas
        yield main_db  # Los tests se ejecutan aquí
        main_db.session.remove()
        main_db.drop_all()  # Limpia la base de datos

@pytest.fixture(scope='function')
def session(db, app):
    """Crea una sesión limpia para cada test."""
    with app.app_context():
        # Clean up any existing data from previous tests in correct order (respecting foreign keys)
        db.session.execute(post_categories.delete())
        db.session.query(Comment).delete()
        db.session.query(Post).delete()
        db.session.query(Category).delete()
        db.session.query(UserCredentials).delete()
        db.session.query(User).delete()
        db.session.commit()
        
        yield db.session
        
        # Rollback any uncommitted changes
        db.session.rollback()

@pytest.fixture(scope='function')
def client(app, session):
    """Un cliente de prueba para hacer peticiones a la API."""
    with app.app_context():
        yield app.test_client()

@pytest.fixture(scope='function')
def normal_user(session):
    """Crea un usuario con rol 'user' en la DB."""
    user = User(username='testuser', email='test@user.com')
    session.add(user)
    session.commit()
    
    cred = UserCredentials(
        user_id=user.id,
        password_hash=generate_password_hash('password123'),
        role='user'
    )
    session.add(cred)
    session.commit()
    
    user.credential = cred 
    return user

@pytest.fixture(scope='function')
def admin_user(session):
    """Crea un usuario con rol 'admin' en la DB."""
    user = User(username='adminuser', email='admin@user.com')
    session.add(user)
    session.commit()
    
    cred = UserCredentials(
        user_id=user.id,
        password_hash=generate_password_hash('password123'),
        role='admin'
    )
    session.add(cred)
    session.commit()

    user.credential = cred
    return user

@pytest.fixture(scope='function')
def moderator_user(session):
    """Crea un usuario con rol 'moderator' en la DB."""
    user = User(username='moderatoruser', email='moderator@user.com')
    session.add(user)
    session.commit()
    
    cred = UserCredentials(
        user_id=user.id,
        password_hash=generate_password_hash('password123'),
        role='moderator'
    )
    session.add(cred)
    session.commit()

    user.credential = cred
    return user

@pytest.fixture(scope='function')
def auth_headers_user(client, normal_user):
    """Inicia sesión como 'user' y devuelve los headers de autenticación."""
    res = client.post('/login', json={
        'email': normal_user.email,
        'password': 'password123'
    })
    token = res.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture(scope='function')
def auth_headers_admin(client, admin_user):
    """Inicia sesión como 'admin' y devuelve los headers de autenticación."""
    res = client.post('/login', json={
        'email': admin_user.email,
        'password': 'password123'
    })
    token = res.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}