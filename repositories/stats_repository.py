from models import db, Post, Comment, User

class StatsRepository:
    @staticmethod
    def get_total_posts():
        return Post.query.count()

    @staticmethod
    def get_total_comments():
        return Comment.query.count()

    @staticmethod
    def get_total_users():
        return User.query.count()

    @staticmethod
    def get_posts_last_week():
        return Post.query.filter(
            Post.date_created >= db.func.now() - db.text('INTERVAL 7 DAY')
        ).count()
