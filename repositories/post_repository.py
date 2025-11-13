from app import db
from models import Post, Category

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