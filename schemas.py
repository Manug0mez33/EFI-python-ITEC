from marshmallow import Schema, fields
from marshmallow import validate
from app import db
from models import User, Comment

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    email = fields.Str(required=True)
    is_active = fields.Bool()
    role = fields.Str(attribute='credential.role', dump_only=True)
    created_at = fields.DateTime(dump_only=True)

class RegisterSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True) 
    role = fields.Str(required=True, load_only=True)

class LoginSchema(Schema):
    email = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    
class CommentSchema(Schema):
    id = fields.Int(dump_only=True)
    content = fields.Str(required=True)
    date_created = fields.DateTime(dump_only=True)
    post_id = fields.Int(load_only=True)
    user = fields.Nested(UserSchema(only=('id', 'username')), dump_only=True)

class CategorySchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    is_visible = fields.Bool(dump_only=True)

class PostSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True)
    content = fields.Str(required=True)
    date_created = fields.DateTime(dump_only=True)
    user = fields.Nested(UserSchema(only=('id', 'username')), dump_only=True)
    comments = fields.Method('get_visible_comments', dump_only=True)
    user_id = fields.Int(load_only=True)
    categories = fields.List(fields.Int(), load_only=True)
    categories_data = fields.Nested(
        CategorySchema(many=True), 
        dump_only=True, 
        attribute="categories"
    )

    def get_visible_comments(self, post_obj):
        try:
            visible_comments = post_obj.comments.filter_by(
                is_visible=True
            ).order_by(Comment.date_created.asc()).all()
            return CommentSchema(many=True).dump(visible_comments)
        except Exception as e:
            print(f"Error al serializar comentarios visibles: {e}")
            return []

class RoleUpdateSchema(Schema):
    role = fields.Str(required=True, validate=validate.OneOf(['admin', 'user', 'moderator']))

