import datetime
from bson.json_util import default, object_hook as bson_hook
import simplejson
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


class JSONDecoder(simplejson.JSONDecoder):

    def decode(self, s):
        def object_hook(obj):
            return bson_hook(obj)

        return simplejson.loads(s, object_hook=self.object_hook)
