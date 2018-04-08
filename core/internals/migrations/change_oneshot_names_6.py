from mongoengine.connection import connect, get_db
from core.config.config import yeti_config
import re

__description__ = ("Changes some OneShotEntry names that were duplicate and"
                   " rebuilds all indexes")

changes = [
    ('DNSDBPassiveDns', 'DNSDB Passive DNS'),
    ('DTReverseNS', 'DomanTools Reverse NS'),
    ('DTReverseWhois', 'DomainTools Reverse Whois'),
    ('DTWhois', 'DomainTools Whois'),
    ('PassiveTotalPassiveDNS', 'PassiveTotal Passive DNS'),
    ('PassiveTotalWhois', 'PassiveTotal Whois'),
    ('PassiveTotalReverseWhois', 'PassiveTotal Reverse Whois'),
    ('PassiveTotalReverseNS', 'PassiveTotal Reverse NS'),
]


def change_oneshot_entries(db):
    for classname, newname in changes:
        db.one_shot_entry.find_one_and_update(
            {'_cls': re.compile(classname)},
            {'$set': {'name': newname}}
        )

def change_feed_name(db):
    db.schedule_entry.find_one_and_update(
        {'name': 'Hybdrid-Analysis'},
        {'$set': {
            'name': 'HybridAnalysis',
            '_cls': 'ScheduleEntry.Feed.HybridAnalysis'
            }
        }
    )

def correct_feed_objects():
    from core.observables import Observable
    for observable in Observable.objects.filter(context__source='Hybdrid-Analysis'):
        for ctx in observable.context:
            if ctx['source'] == 'Hybdrid-Analysis':
                ctx['source'] = 'HybridAnalysis'
        observable.value = observable.value.replace('FILE: ', 'FILE:')
        observable.save()

def migrate():
    connect(
        yeti_config.mongodb.database,
        host=yeti_config.mongodb.host,
        port=yeti_config.mongodb.port,
        username=yeti_config.mongodb.username,
        password=yeti_config.mongodb.password,
        connect=True)
    db = get_db()
    # Drop these indexes as they have changed
    db.schedule_entry.drop_indexes()
    db.one_shot_entry.drop_indexes()
    db.inline_analytics.drop_indexes()
    db.attached_file.drop_indexes()
    change_oneshot_entries(db)
    change_feed_name(db)
    correct_feed_objects()
