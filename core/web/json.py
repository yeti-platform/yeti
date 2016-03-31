import datetime
from bson.json_util import default, object_hook as bson_hook
import simplejson
from bson.objectid import ObjectId
from bson.dbref import DBRef

from core.helpers import iterify
from core.database import Node, Link, YetiDocument

def recursive_encoder(objects, template=None, ctx=None):

    if isinstance(objects, dict):
        for (key, value) in objects.items():
            objects[key] = recursive_encoder(value)
        return objects

    elif isinstance(objects, list):
        return [recursive_encoder(o) for o in objects]

    elif isinstance(objects, tuple):
        return tuple(recursive_encoder(o) for o in objects)

    elif isinstance(objects, (Node, Link, YetiDocument)):
        data = []
        for o in iterify(objects):
            if hasattr(o, "info"):
                info = o.info()
            else:
                info = o.to_mongo()
                
            if hasattr(o, 'uri'):
                info['uri'] = o.uri
            data.append(info)

        if len(data) == 1:
            data = data[0]

        return data
    else:
        return objects


def to_json(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, DBRef):
        return {'collection': obj.collection, 'id': str(obj.id)}
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, set):
        return list(obj)
    else:
        return default(obj)


class JSONDecoder(simplejson.JSONDecoder):

    def decode(self, s):
        def object_hook(obj):
            return bson_hook(obj)

        return simplejson.loads(s, object_hook=self.object_hook)
