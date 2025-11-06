from models import db, Category

class CategoryRepository:
    @staticmethod
    def get_all():
        return Category.query.all()

    @staticmethod
    def get_by_id(category_id):
        return Category.query.get_or_404(category_id)

    @staticmethod
    def get_by_name(name):
        return Category.query.filter_by(name=name).first()

    @staticmethod
    def create(name):
        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()
        return new_category

    @staticmethod
    def update(category, name):
        category.name = name
        db.session.commit()
        return category

    @staticmethod
    def delete(category):
        db.session.delete(category)
        db.session.commit()
