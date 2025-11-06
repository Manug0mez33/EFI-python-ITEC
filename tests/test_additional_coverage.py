# tests/test_additional_coverage.py
from models import Post, User, Comment, Category

# --- Tests de Refresh Token ---

def test_refresh_token(client, auth_headers_user):
    """Prueba el refresh token endpoint."""
    # Primero obtenemos el refresh token del login
    res = client.post('/login', json={
        'email': 'test@user.com',
        'password': 'password123'
    })
    refresh_token = res.get_json()['refresh_token']
    
    # Usamos el refresh token para obtener un nuevo access token
    res = client.post('/refresh', headers={
        'Authorization': f'Bearer {refresh_token}'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert 'access_token' in data


# --- Tests de Validación de Errores ---

def test_create_post_validation_error(client, auth_headers_user):
    """Prueba crear un post con datos inválidos."""
    res = client.post('/post', json={
        'title': 'Valid Title'
        # Falta 'content' que es requerido
    }, headers=auth_headers_user)
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data


def test_register_validation_error(client):
    """Prueba registro con datos inválidos."""
    res = client.post('/register', json={
        'username': 'testuser'
        # Faltan campos requeridos
    })
    assert res.status_code == 400
    data = res.get_json()
    assert 'errors' in data


def test_register_duplicate_email(client, normal_user):
    """Prueba registro con email duplicado."""
    res = client.post('/register', json={
        'username': 'anotheruser',
        'email': normal_user.email,  # Email ya existente
        'password': 'password123',
        'role': 'user'
    })
    assert res.status_code == 400
    data = res.get_json()
    assert 'message' in data


# --- Tests de Post Detail (Update y Delete) ---

def test_update_post(client, auth_headers_user, normal_user, session):
    """Prueba actualizar un post propio."""
    # Crear un post
    post = Post(title='Original Title', content='Original content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    # Actualizar el post
    res = client.put(f'/post/{post.id}', json={
        'title': 'Updated Title',
        'content': 'Updated content'
    }, headers=auth_headers_user)
    
    assert res.status_code == 200
    data = res.get_json()
    assert data['title'] == 'Updated Title'


def test_update_post_not_owner(client, auth_headers_user, admin_user, session):
    """Prueba que un usuario no puede actualizar el post de otro."""
    # Crear un post del admin
    post = Post(title='Admin Post', content='Content', user_id=admin_user.id)
    session.add(post)
    session.commit()
    
    # Intentar actualizar como user normal
    res = client.put(f'/post/{post.id}', json={
        'title': 'Hacked Title',
        'content': 'Hacked content'
    }, headers=auth_headers_user)
    
    assert res.status_code == 403


def test_delete_post(client, auth_headers_user, normal_user, session):
    """Prueba eliminar un post propio."""
    post = Post(title='To Delete', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    post_id = post.id
    
    res = client.delete(f'/post/{post_id}', headers=auth_headers_user)
    assert res.status_code == 200
    
    # Verificar que fue eliminado
    deleted_post = session.query(Post).filter_by(id=post_id).first()
    assert deleted_post is None


def test_get_post_detail(client, normal_user, session):
    """Prueba obtener un post específico."""
    post = Post(title='Test Post', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    res = client.get(f'/post/{post.id}')
    assert res.status_code == 200
    data = res.get_json()
    assert data['title'] == 'Test Post'


# --- Tests de Comentarios ---

def test_create_comment(client, auth_headers_user, normal_user, session):
    """Prueba crear un comentario."""
    post = Post(title='Post', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    res = client.post(f'/post/{post.id}/comments', json={
        'content': 'Great post!'
    }, headers=auth_headers_user)
    
    assert res.status_code == 201
    data = res.get_json()
    assert data['content'] == 'Great post!'


def test_get_comments(client, normal_user, session):
    """Prueba obtener comentarios de un post."""
    post = Post(title='Post', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    comment = Comment(content='Comment 1', post_id=post.id, user_id=normal_user.id)
    session.add(comment)
    session.commit()
    
    res = client.get(f'/post/{post.id}/comments')
    assert res.status_code == 200
    data = res.get_json()
    assert len(data) == 1
    assert data[0]['content'] == 'Comment 1'


def test_delete_comment_as_owner(client, auth_headers_user, normal_user, session):
    """Prueba eliminar un comentario propio."""
    post = Post(title='Post', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    comment = Comment(content='My comment', post_id=post.id, user_id=normal_user.id)
    session.add(comment)
    session.commit()
    comment_id = comment.id
    
    res = client.delete(f'/comments/{comment_id}', headers=auth_headers_user)
    assert res.status_code == 200


# --- Tests de Categorías ---

def test_get_categories(client, session):
    """Prueba listar categorías."""
    cat1 = Category(name='Technology')
    cat2 = Category(name='Sports')
    session.add_all([cat1, cat2])
    session.commit()
    
    res = client.get('/category')
    assert res.status_code == 200
    data = res.get_json()
    assert len(data) >= 2


def test_create_category_as_admin(client, auth_headers_admin):
    """Prueba crear una categoría como admin."""
    res = client.post('/category', json={
        'name': 'New Category'
    }, headers=auth_headers_admin)
    
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] == True
    assert data['category']['name'] == 'New Category'


def test_create_category_as_user(client, auth_headers_user):
    """Prueba que un usuario normal no puede crear categorías."""
    res = client.post('/category', json={
        'name': 'Forbidden Category'
    }, headers=auth_headers_user)
    
    assert res.status_code == 403


def test_update_category_as_admin(client, auth_headers_admin, session):
    """Prueba actualizar una categoría como admin."""
    cat = Category(name='Old Name')
    session.add(cat)
    session.commit()
    
    res = client.put(f'/category/{cat.id}', json={
        'name': 'New Name'
    }, headers=auth_headers_admin)
    
    assert res.status_code == 200


def test_delete_category_as_admin(client, auth_headers_admin, session):
    """Prueba eliminar una categoría como admin."""
    cat = Category(name='To Delete')
    session.add(cat)
    session.commit()
    cat_id = cat.id
    
    res = client.delete(f'/category/{cat_id}', headers=auth_headers_admin)
    assert res.status_code == 200


# --- Tests de User API ---

def test_get_users_as_admin(client, auth_headers_admin):
    """Prueba listar usuarios como admin."""
    res = client.get('/users', headers=auth_headers_admin)
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)


def test_get_users_as_user(client, auth_headers_user):
    """Prueba que un usuario normal no puede listar usuarios."""
    res = client.get('/users', headers=auth_headers_user)
    assert res.status_code == 403


def test_update_user_role_as_admin(client, auth_headers_admin, normal_user):
    """Prueba actualizar el rol de un usuario como admin."""
    res = client.patch(f'/users/{normal_user.id}/role', json={
        'role': 'moderator'
    }, headers=auth_headers_admin)
    
    assert res.status_code == 200
    data = res.get_json()
    assert 'message' in data


# --- Tests de Stats API ---

def test_get_stats_as_admin(client, auth_headers_admin, normal_user, session):
    """Prueba obtener estadísticas como admin."""
    # Crear algunos datos
    post = Post(title='Test', content='Content', user_id=normal_user.id)
    session.add(post)
    session.commit()
    
    res = client.get('/stats', headers=auth_headers_admin)
    assert res.status_code == 200
    data = res.get_json()
    assert 'total_posts' in data
    assert 'total_comments' in data
    assert 'total_users' in data
    assert 'posts_last_week' in data


def test_get_stats_as_user(client, auth_headers_user):
    """Prueba que un usuario normal no puede ver estadísticas."""
    res = client.get('/stats', headers=auth_headers_user)
    assert res.status_code == 403


# --- Tests de filtro por categoría ---

def test_filter_posts_by_category(client, normal_user, session):
    """Prueba filtrar posts por categoría."""
    cat = Category(name='TestCategory')
    session.add(cat)
    session.commit()
    
    post = Post(title='Categorized Post', content='Content', user_id=normal_user.id)
    post.categories.append(cat)
    session.add(post)
    session.commit()
    
    res = client.get(f'/post?category_name=TestCategory')
    assert res.status_code == 200
    data = res.get_json()
    assert len(data['posts']) >= 1
