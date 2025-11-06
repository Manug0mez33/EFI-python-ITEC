import pytest
from app import app as main_app 
from app import db as main_db
from models import User, UserCredentials  
from werkzeug.security import generate_password_hash  

@pytest.fixture(scope='session')
def app():
    """Configura la app de Flask para pruebas."""
    main_app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://manu:1234@localhost/EFI_test'
    main_app.config['TESTING'] = True  
    main_app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 30  
    
    yield main_app

@pytest.fixture(scope='session')
def db(app):
    """Configura la base de datos para pruebas."""
    with app.app_context():
        main_db.create_all()  # Crea todas las tablas
        yield main_db  # Los tests se ejecutan aquí
        main_db.session.remove()
        main_db.drop_all()  # Limpia la base de datos

@pytest.fixture(scope='function')
def session(db):
    """Crea una sesión limpia para cada test."""
    connection = db.engine.connect()
    transaction = connection.begin()
    
    options = dict(bind=connection, binds={})
    session = db.create_scoped_session(options=options)
    
    db.session = session

    yield session

    transaction.rollback()
    connection.close()
    session.remove()

@pytest.fixture(scope='session')
def client(app):
    """Un cliente de prueba para hacer peticiones a la API."""
    return app.test_client()

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