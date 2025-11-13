from repositories.post_repository import PostRepository
from repositories.comment_repository import CommentRepository
from repositories.user_repository import UserRepository

class StatsService:
    def __init__(self):
        self.post_repository = PostRepository()
        self.comment_repository = CommentRepository()
        self.user_repository = UserRepository()

    def get_dashboard_stats(self):
        return {
            'total_posts': self.post_repository.count_published(),
            'total_comments': self.comment_repository.count_visible(),
            'total_users': self.user_repository.count_active(),
            'posts_last_week': self.post_repository.count_last_week()
        }