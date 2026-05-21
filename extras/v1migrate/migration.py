import pymongo
import pprint
from core.schemas.observable import Observable
from bson.dbref import DBRef
from bson.objectid import ObjectId
from bson.json_util import dumps
from bson.son import SON

import cProfile

db = pymongo.MongoClient(
    host="192.168.48.6",
    port=27017,
).yeti


# list collection
# print(db.list_collection_names())

def process_observable(legacy_observable, no_links=False):
    value = legacy_observable['value']
    tags = legacy_observable['tags']
    context = legacy_observable['context']

    obj = Observable.add_text(value)
    obj.created = legacy_observable['created']
    # obj.save()
    for tag in tags:
        obj.observable_tag(
            tag['name'],
            fresh=tag['fresh'],
            first_seen=tag['first_seen'],
            last_seen=tag['last_seen'])

    for context in context:
        obj = obj.add_context(context['source'], context)

    return obj

def main():
    for link in db.link.find()[:1000]:
    # for link in db.link.find({'value': 'netsolhost.com'}):
        src = db[link['src'].collection].find_one({'_id': link['src'].id})
        dst = db[link['dst'].collection].find_one({'_id': link['dst'].id})
        try:
            if src['_cls'].lower().startswith('observable'):
                src = process_observable(src)
            else:
                pprint.pprint(src, indent=4)
                break
        except Exception as e:
            import traceback
            traceback.print_exc()
            print('Error when importing', src['value'])
            break

        if dst['_cls'].lower().startswith('observable'):
            dst = process_observable(dst)
        else:
            print(dst['value'])
            break

        try:
            for h in link['history']:
                src.link_to(
                    dst,
                    h.get('type', h['description']),
                    h['description'],
                    created=h['first_seen'],
                    modified=h['last_seen'])
        except Exception as e:
            print(e)
            pprint.pprint(link, indent=4)
            break

        dst = link['dst']
        # pretty print
        # save_observable(o)

main()
