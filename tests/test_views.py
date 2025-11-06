# tests/test_views.py
from models import Post, User
from app import db
# No necesitas importar 'db' o 'client', pytest los inyecta.

# --- Tests de Autenticación y Registro ---

def test_register_user(client, session):
    """Prueba el registro de un nuevo usuario."""
    res = client.post('/register', json={
        'username': 'newuser',
        'email': 'new@user.com',
        'password': 'password123',
        'role': 'user'
    })
    assert res.status_code == 201
    data = res.get_json()
    assert data['user']['username'] == 'newuser'

def test_login_user(client, normal_user):
    """Prueba el login de un usuario existente."""
    res = client.post('/login', json={
        'email': normal_user.email,
        'password': 'password123'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'access_token' in data
    assert 'refresh_token' in data

def test_login_invalid_password(client, normal_user):
    """Prueba el login con contraseña incorrecta."""
    res = client.post('/login', json={
        'email': normal_user.email,
        'password': 'wrongpassword'
    })
    assert res.status_code == 401 # Credenciales inválidas

# --- Tests de Posts (Cubre paginación y filtros) ---

def test_create_post(client, auth_headers_user, normal_user):
    """Prueba crear un post estando autenticado."""
    res = client.post('/post', json={
        'title': 'Mi Primer Post de Test',
        'content': 'Contenido...',
        'categories': [] # Asumiendo que categorías es opcional o vacío
    }, headers=auth_headers_user)
    
    assert res.status_code == 201
    data = res.get_json()
    assert data['title'] == 'Mi Primer Post de Test'
    assert data['user']['id'] == normal_user.id

def test_create_post_unauthenticated(client):
    """Prueba crear un post sin token."""
    res = client.post('/post', json={
        'title': 'Post Fantasma',
        'content': '...'
    })
    assert res.status_code == 401 # Sin autorización

def test_get_posts_pagination(client, session, normal_user):
    """Prueba la paginación del listado de posts."""
    # Creamos 15 posts
    for i in range(15):
        post = Post(title=f'Post {i}', content='...', user_id=normal_user.id)
        session.add(post)
    session.commit()
    
    # Pedimos la página 2, con 5 posts por página
    res = client.get('/post?page=2&per_page=5')
    assert res.status_code == 200
    data = res.get_json()
    
    assert len(data['posts']) == 5 # Debe haber 5 posts en la página 2
    assert data['pagination']['current_page'] == 2
    assert data['pagination']['total_items'] == 15
    assert data['pagination']['total_pages'] == 3

def test_get_posts_filter_by_author(client, session, normal_user, admin_user):
    """Prueba el filtro por autor (username)."""
    session.add(Post(title='Post de User', content='...', user_id=normal_user.id))
    session.add(Post(title='Post de Admin', content='...', user_id=admin_user.id))
    session.commit()
    
    # Filtra por el username del admin
    res = client.get(f'/post?author_username={admin_user.username}')
    assert res.status_code == 200
    data = res.get_json()
    
    assert len(data['posts']) == 1
    assert data['posts'][0]['title'] == 'Post de Admin'
    assert data['pagination']['total_items'] == 1

# --- Tests de Permisos (Clave para cobertura) ---

def test_get_own_user_detail(client, auth_headers_user, normal_user):
    """Prueba que un usuario puede ver su propio perfil."""
    res = client.get(f'/users/{normal_user.id}', headers=auth_headers_user)
    assert res.status_code == 200
    assert res.get_json()['username'] == normal_user.username

def test_get_other_user_detail_as_user(client, auth_headers_user, admin_user):
    """Prueba que un usuario NO PUEDE ver el perfil de OTRO."""
    res = client.get(f'/users/{admin_user.id}', headers=auth_headers_user)
    # Esto prueba tu lógica 'is_admin_or_owner'
    assert res.status_code == 403 # Acceso denegado

def test_get_other_user_detail_as_admin(client, auth_headers_admin, normal_user):
    """Prueba que un admin SÍ PUEDE ver el perfil de OTRO."""
    res = client.get(f'/users/{normal_user.id}', headers=auth_headers_admin)
    assert res.status_code == 200
    assert res.get_json()['username'] == normal_user.username

def test_delete_user_as_admin(client, auth_headers_admin, normal_user):
    """Prueba que un admin puede desactivar un usuario."""
    res = client.delete(f'/users/{normal_user.id}', headers=auth_headers_admin)
    assert res.status_code == 200
    assert res.get_json()['message'] == 'Usuario desactivado'
    
    session = db.session
    # Verifica que el usuario está inactivo en la DB
    user_in_db = session.get(User, normal_user.id)
    assert user_in_db.is_active == False