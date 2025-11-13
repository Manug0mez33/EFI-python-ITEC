from models import Category
from repositories.category_repository import CategoryRepository

class CategoryService:
    def __init__(self):
        self.category_repository = CategoryRepository()

    def get_all_categories(self):
        return self.category_repository.get_all_visible()

    def create_category(self, name):
        if self.category_repository.get_by_name(name):
            raise ValueError("Esa categoría ya existe.")
        
        new_category = Category(name=name)
        return self.category_repository.create(new_category)

    def update_category(self, category_id, new_name):
        category = self.category_repository.get_by_id_or_404(category_id)

        existing = self.category_repository.get_by_name(new_name)
        if existing and existing.id != category_id:
             raise ValueError("Ya existe otra categoría con ese nombre.")

        category.name = new_name
        self.category_repository.update()
        return category

    def delete_category(self, category_id):
        category = self.category_repository.get_by_id_or_404(category_id)
        category.is_visible = False
        self.category_repository.update()