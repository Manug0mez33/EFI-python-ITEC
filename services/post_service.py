from repositories.post_repository import PostRepository
from schemas import PostSchema

class PostService:
    def __init__(self):
        self.post_repository = PostRepository()

    def get_all_posts(self, page, per_page, author_username, category_name):
        paginated_posts = self.post_repository.get_all(page, per_page, author_username, category_name)
        return {
            'posts': PostSchema(many=True).dump(paginated_posts.items),
            'pagination': {
                'total_pages': paginated_posts.pages,
                'total_items': paginated_posts.total,
                'current_page': paginated_posts.page,
                'per_page': paginated_posts.per_page,
                'has_next': paginated_posts.has_next,
                'has_prev': paginated_posts.has_prev
            }
        }

    def get_post_by_id(self, post_id):
        post = self.post_repository.get_by_id(post_id)
        return PostSchema().dump(post)

    def create_post(self, title, content, user_id):
        new_post = self.post_repository.create(title, content, user_id)
        return PostSchema().dump(new_post)

    def update_post(self, post_id, title, content):
        post = self.post_repository.get_by_id(post_id)
        updated_post = self.post_repository.update(post, title, content)
        return PostSchema().dump(updated_post)

    def delete_post(self, post_id):
        post = self.post_repository.get_by_id(post_id)
        self.post_repository.delete(post)
