from models import db, Comment

class CommentRepository:
    @staticmethod
    def get_by_id(comment_id):
        return Comment.query.get_or_404(comment_id)

    @staticmethod
    def get_all_by_post_id(post_id):
        return Comment.query.filter_by(post_id=post_id).all()

    @staticmethod
    def create(content, post_id, user_id):
        new_comment = Comment(
            content=content,
            post_id=post_id,
            user_id=user_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return new_comment

    @staticmethod
    def delete(comment):
        db.session.delete(comment)
        db.session.commit()
