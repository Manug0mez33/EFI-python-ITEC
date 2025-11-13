from app import db
from models import Category

class CategoryRepository:
    def get_all_visible(self):
        return Category.query.filter_by(is_visible=True).all()

    def get_by_id_or_404(self, category_id):
        return Category.query.get_or_404(category_id)

    def get_by_name(self, name):
        return Category.query.filter_by(name=name).first()

    def create(self, category):
        db.session.add(category)
        db.session.commit()
        return category

    def update(self):
        db.session.commit()