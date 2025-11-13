from app import db
from models import Comment

class CommentRepository:
    def create(self, comment):
        db.session.add(comment)
        db.session.commit()
        return comment

    def get_by_id_or_404(self, comment_id):
        return Comment.query.get_or_404(comment_id)

    def delete_logical(self, comment):
        comment.is_visible = False
        db.session.commit()

    def update(self):
        db.session.commit()