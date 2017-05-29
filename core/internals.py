from mongoengine import *

class Configuration(Document):
    db_version = IntField(default=0)
    name = StringField(default="default")
