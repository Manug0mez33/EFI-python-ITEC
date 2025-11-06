from models import db, Post, User

class PostRepository:
    @staticmethod
    def get_all(page, per_page, author_username, category_name):
        query = Post.query

        if author_username:
            query = query.join(User).filter(User.username == author_username)

        if category_name:
            query = query.filter(Post.categories.any(name=category_name))

        query = query.order_by(Post.date_created.desc())

        return query.paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_by_id(post_id):
        return Post.query.get_or_404(post_id)

    @staticmethod
    def create(title, content, user_id):
        new_post = Post(
            title=title,
            content=content,
            user_id=user_id
        )
        db.session.add(new_post)
        db.session.commit()
        return new_post

    @staticmethod
    def update(post, title, content):
        post.title = title
        post.content = content
        db.session.commit()
        return post

    @staticmethod
    def delete(post):
        db.session.delete(post)
        db.session.commit()
