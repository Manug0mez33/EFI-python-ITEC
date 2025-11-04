from marshmallow import Schema, fields

from app import db
from models import User

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    email = fields.Str(required=True)
    is_active = fields.Bool()

class RegisterSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)  # <-- importante


class PostSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True)
    content = fields.Str(required=True)
    date_created = fields.DateTime(dump_only=True)
    user_id = fields.Int(load_only=True)
    categories = fields.List(fields.Int(), load_only=True)

class CommentSchema(Schema):
    id = fields.Int(dump_only=True)
    content = fields.Str(required=True)
    date_created = fields.DateTime(dump_only=True)
    post_id = fields.Int(load_only=True)

class CategorySchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)