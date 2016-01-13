import datetime
from bson.json_util import default, loads
from bson.objectid import ObjectId
from bson.dbref import DBRef


def to_json(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, DBRef):
        return {'collection': obj.collection, 'id': str(obj.id)}
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return default(obj)


class JSONDecoder:
    def __init__(self, *args, **kwargs):
        pass

    def decode(self, s):
        return loads(s)
