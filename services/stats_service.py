from repositories.stats_repository import StatsRepository

class StatsService:
    def __init__(self):
        self.stats_repository = StatsRepository()

    def get_stats(self):
        total_posts = self.stats_repository.get_total_posts()
        total_comments = self.stats_repository.get_total_comments()
        total_users = self.stats_repository.get_total_users()
        posts_last_week = self.stats_repository.get_posts_last_week()

        return {
            'total_posts': total_posts,
            'total_comments': total_comments,
            'total_users': total_users,
            'posts_last_week': posts_last_week
        }
