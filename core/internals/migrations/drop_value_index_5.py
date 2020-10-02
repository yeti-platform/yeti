from mongoengine.connection import connect, get_db
from core.config.config import yeti_config

__description__ = "Drop the value_1 index"


def migrate():
    connect(
        yeti_config.mongodb.database,
        host=yeti_config.mongodb.host,
        port=yeti_config.mongodb.port,
        username=yeti_config.mongodb.username,
        password=yeti_config.mongodb.password,
        connect=True,
    )
    db = get_db()
    for i in list(db.observable.list_indexes()):
        if i.to_dict()["name"] == "value_1":
            db.observable.drop_index("value_1")
