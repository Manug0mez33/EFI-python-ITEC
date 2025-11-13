from models import Comment, Post
from repositories.comment_repository import CommentRepository

class CommentService:
    def __init__(self):
        self.comment_repository = CommentRepository()

    def get_post_comments(self, post_id):
        post = Post.query.get_or_404(post_id)
        return post.comments.filter_by(is_visible=True)

    def create_comment(self, content, post_id, user_id):
        post = Post.query.get_or_404(post_id)
        
        new_comment = Comment(
            content=content,
            post_id=post_id,
            user_id=user_id,
            is_visible=True
        )
        return self.comment_repository.create(new_comment)

    def update_comment(self, comment_id, new_content, user_id, role):
        comment = self.comment_repository.get_by_id_or_404(comment_id)

        is_owner = comment.user_id == user_id
        is_admin = role == 'admin'
        
        if not (is_owner or is_admin):
             raise PermissionError("No tienes permiso para editar este comentario")

        comment.content = new_content
        self.comment_repository.update() 
        return comment

    def delete_comment(self, comment_id, user_id, role):
        comment = self.comment_repository.get_by_id_or_404(comment_id)

        is_owner = comment.user_id == user_id
        is_admin_or_mod = role in ['admin', 'moderator']

        if not (is_owner or is_admin_or_mod):
            raise PermissionError("No tienes permiso para borrar este comentario")

        self.comment_repository.delete_logical(comment)