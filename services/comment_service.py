from repositories.comment_repository import CommentRepository
from schemas import CommentSchema

class CommentService:
    def __init__(self):
        self.comment_repository = CommentRepository()

    def get_comments_by_post(self, post_id):
        # We need to get the post to get the comments, but the logic is in the view for now
        # This should be improved by getting the post from the post_service
        comments = self.comment_repository.get_all_by_post_id(post_id)
        return CommentSchema(many=True).dump(comments)

    def create_comment(self, content, post_id, user_id):
        new_comment = self.comment_repository.create(content, post_id, user_id)
        return CommentSchema().dump(new_comment)

    def delete_comment(self, comment_id):
        comment = self.comment_repository.get_by_id(comment_id)
        self.comment_repository.delete(comment)
