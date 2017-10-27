import logging
import requests
from csv import DictReader
from urlparse import urljoin
from mongoengine import DictField
from datetime import date, timedelta

from core.feed import Feed
from core.observables import Ip, Url, Hostname, Hash, Email, Bitcoin
from core.config.config import yeti_config


class MispFeed(Feed):

    last_runs = DictField()

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "MispFeed",
        "description": "Parses events from a given MISP instance",
        "source": "MISP"
    }

    TYPES_TO_IMPORT = {
        'domain': Hostname,
        'ip-dst': Ip,
        'ip-src': Ip,
        'url': Url,
        'hostname': Hostname,
        'md5': Hash,
        'sha1': Hash,
        'sha256': Hash,
        'btc': Bitcoin,
        'email-src': Email,
        'email-dst': Email
    }

    def __init__(self, *args, **kwargs):
        super(MispFeed, self).__init__(*args, **kwargs)
        self.get_instances()

    def get_instances(self):
        self.instances = {}

        for instance in yeti_config.get('misp', 'instances', '').split(','):
            config = {
                'url': yeti_config.get(instance, 'url'),
                'key': yeti_config.get(instance, 'key'),
                'name': yeti_config.get(instance, 'name') or instance,
                'organisations': {}
            }

            if config['url'] and config['key']:
                self.instances[instance] = config

    def last_run_for(self, instance):
        last_run = [int(part) for part in self.last_runs[instance].split('-')]

        return date(*last_run)

    def get_organisations(self, instance):
        url = urljoin(self.instances[instance]['url'], '/organisations/index/scope:all')
        headers = {
            'Authorization': self.instances[instance]['key'],
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        orgs = requests.get(url, headers=headers, proxies=yeti_config.proxy).json()

        for org in orgs:
            org_id = org['Organisation']['id']
            org_name = org['Organisation']['name']
            self.instances[instance]['organisations'][org_id] = org_name

    def week_events(self, instance):
        one_week = timedelta(days=7)
        url = urljoin(self.instances[instance]['url'], '/events/csv/download')
        headers = {'Authorization': self.instances[instance]['key']}
        to = date.today()
        fromdate = to - timedelta(days=6)
        time_filter = {'request': {'ignore': True, 'includeContext': True}}

        while True:
            imported = 0

            time_filter['request']['to'] = to.isoformat()
            time_filter['request']['from'] = fromdate.isoformat()
            r = requests.post(url, headers=headers, json=time_filter, proxies=yeti_config.proxy)

            try:
                msg = r.json()
                raise AttributeError(msg['message'])
            except ValueError:
                lines = [l for l in r.content.splitlines() if '\0' not in l]
                csvreader = DictReader(lines)

                for row in csvreader:
                    self.analyze(row, instance)
                    imported += 1

                yield fromdate, to, imported
                to = to - one_week
                fromdate = fromdate - one_week

    def get_last_events(self, instance):
        logging.debug("Getting last events for {}".format(instance))
        last_run = self.last_run_for(instance)
        seen_last_run = False

        for date_from, date_to, imported in self.week_events(instance):
            logging.debug("Imported {} attributes from {} to {}".format(imported, date_from, date_to))

            if seen_last_run:
                break

            if date_from <= last_run <= date_to:
                seen_last_run = True

    def get_all_events(self, instance):
        logging.debug("Getting all events for {}".format(instance))
        had_results = True

        for date_from, date_to, imported in self.week_events(instance):
            logging.debug("Imported {} attributes from {} to {}".format(imported, date_from, date_to))

            if imported == 0:
                if had_results:
                    had_results = False
                else:
                    break
            else:
                had_results = True

    def update(self):
        for instance in self.instances:
            logging.debug("Processing instance {}".format(instance))
            self.get_organisations(instance)
            if instance in self.last_runs:
                self.get_last_events(instance)
            else:
                self.get_all_events(instance)

            self.modify(**{"set__last_runs__{}".format(instance): date.today().isoformat()})

    def analyze(self, attribute, instance):
        if 'type' in attribute and attribute['type'] in self.TYPES_TO_IMPORT:
            context = {
                'org': attribute['event_source_org'],
                'id': attribute['event_id'],
                'link': urljoin(self.instances[instance]['url'], '/events/{}'.format(attribute['event_id'])),
                'date': attribute['event_date'],
                'source': self.instances[instance]['name'],
                'description': attribute['event_info'],
                'comment': attribute['comment']
            }

            try:
                klass = self.TYPES_TO_IMPORT[attribute['type']]
                obs = klass.get_or_create(value=attribute['value'])

                if attribute['category']:
                    obs.tag(attribute['category'].replace(' ', '_'))

                obs.add_context(context)
            except:
                logging.error("{}: error adding {}".format('MispFeed', attribute['value']))
