from app import db
from models import Post, Comment
from sqlalchemy import func

class PostRepository:
    
    def get_all_published(self):
        return Post.query.filter_by(is_published=True)\
                         .order_by(Post.date_created.desc())\
                         .all()

    def get_by_id(self, post_id):
        return Post.query.get(post_id)
    
    def get_by_id_or_404(self, post_id):
        return Post.query.get_or_404(post_id)

    def create(self, post):
        db.session.add(post)
        db.session.commit()
        return post

    def update(self):
        db.session.commit()

    def delete(self, post):
        post.is_published = False
        
        if hasattr(post.comments, 'update'):
             post.comments.update({Comment.is_visible: False}, synchronize_session=False)
        
        db.session.commit()

    def count_published(self):
        return Post.query.filter_by(is_published=True).count()

    def count_last_week(self):
        from app import db 
        return Post.query.filter(
            Post.date_created >= func.now() - db.text('INTERVAL 7 DAY'),
            Post.is_published == True
        ).count()
    
