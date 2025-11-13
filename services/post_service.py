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

    def delete_post(self, post_id):
        post = self.post_repository.get_by_id_or_404(post_id)
        
        post.is_published = False
        
        post.comments.update({Comment.is_visible: False}, synchronize_session=False)
        
        self.post_repository.update()