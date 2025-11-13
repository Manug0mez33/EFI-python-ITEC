from repositories.post_repository import PostRepository
from models import Post, Category, Comment, db

class PostService:
    def __init__(self):
        self.post_repository = PostRepository()

    def get_all_posts(self):
        return self.post_repository.get_all_published()

    def get_post(self, post_id):
        return self.post_repository.get_by_id_or_404(post_id)

    def create_post(self, title, content, user_id, category_ids):
        new_post = Post(
            title=title,
            content=content,
            user_id=user_id
        )

        if category_ids:
            categories = Category.query.filter(Category.id.in_(category_ids)).all()
            new_post.categories.extend(categories)

        return self.post_repository.create(new_post)

    def delete_post(self, post_id, user_id, role):
        post = self.post_repository.get_by_id(post_id)
        
        if not post:
            return 

        if post.user_id != user_id and role != 'admin':
            raise PermissionError("No tienes permiso para eliminar este post")

        self.post_repository.delete(post)

    def update_post(self, post_id, data, user_id, role):
        post = self.post_repository.get_by_id(post_id) 

        if not post:
            return None, "Post no encontrado"

        if post.user_id != user_id and role != 'admin':
            raise PermissionError("No tienes permiso para editar este post")

        if 'title' in data:
            post.title = data['title']
        if 'content' in data:
            post.content = data['content']
            
        if 'categories' in data:
            category_ids = data['categories']
            categories_objects = Category.query.filter(Category.id.in_(category_ids)).all()
            
            post.categories = categories_objects

        self.post_repository.update()

        return post