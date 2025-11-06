from repositories.category_repository import CategoryRepository
from schemas import CategorySchema

class CategoryService:
    def __init__(self):
        self.category_repository = CategoryRepository()

    def get_all_categories(self):
        categories = self.category_repository.get_all()
        return CategorySchema(many=True).dump(categories)

    def create_category(self, name):
        if self.category_repository.get_by_name(name):
            return {'message': 'Esa categoría ya existe.'}, 400
        
        new_category = self.category_repository.create(name)
        return CategorySchema().dump(new_category), 201

    def update_category(self, category_id, name):
        category = self.category_repository.get_by_id(category_id)
        updated_category = self.category_repository.update(category, name)
        return CategorySchema().dump(updated_category)

    def delete_category(self, category_id):
        category = self.category_repository.get_by_id(category_id)
        self.category_repository.delete(category)
