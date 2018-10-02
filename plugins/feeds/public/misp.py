import logging
from datetime import date, timedelta
from urlparse import urljoin

import requests
from mongoengine import DictField

from core.config.config import yeti_config
from core.feed import Feed
from core.observables import Ip, Url, Hostname, Hash, Email, Bitcoin


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
        url = urljoin(
            self.instances[instance]['url'], '/organisations/index/scope:all')
        headers = {
            'Authorization': self.instances[instance]['key'],
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        orgs = requests.get(
            url, headers=headers, proxies=yeti_config.proxy).json()

        for org in orgs:
            org_id = org['Organisation']['id']
            org_name = org['Organisation']['name']
            self.instances[instance]['organisations'][org_id] = org_name

    def week_events(self, instance):
        one_week = timedelta(days=7)
        url = urljoin(self.instances[instance]['url'], '/events/restSearch')
        headers = {'Authorization': self.instances[instance]['key']}
        to = date.today()
        fromdate = to - timedelta(days=6)
        time_filter = {'request': {'ignore': True, 'includeContext': True}}

        while True:
            imported = 0

            time_filter['request']['to'] = to.isoformat()
            time_filter['request']['from'] = fromdate.isoformat()
            r = requests.post(
                url,
                headers=headers,
                json=time_filter,
                proxies=yeti_config.proxy)

            if r.status_code == 200:
                results = r.json()

                for event in results['response']:
                    self.analyze(event['Event'], instance)
                    imported += 1

                yield fromdate, to, imported
                to = to - one_week
                fromdate = fromdate - one_week

    def get_last_events(self, instance):
        logging.debug("Getting last events for {}".format(instance))
        last_run = self.last_run_for(instance)
        seen_last_run = False

        for date_from, date_to, imported in self.week_events(instance):
            logging.debug(
                "Imported {} attributes from {} to {}".format(
                    imported, date_from, date_to))

            if seen_last_run:
                break

            if date_from <= last_run <= date_to:
                seen_last_run = True

    def get_all_events(self, instance):
        logging.debug("Getting all events for {}".format(instance))
        had_results = True

        for date_from, date_to, imported in self.week_events(instance):
            logging.debug(
                "Imported {} attributes from {} to {}".format(
                    imported, date_from, date_to))

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

            self.modify(
                **{
                    "set__last_runs__{}".format(instance):
                        date.today().isoformat()
                })

    def analyze(self, event, instance):
        tags = []

        galaxies = self.instances[instance]['galaxy_filter'].split(',')

        for tag in event['Tag']:
            found = False
            for g in galaxies:
                if g in tag['name']:
                    found = True
                    break
            if not found:
                tags.append(tag['name'])

        for attribute in event['Attribute']:
            if 'type' in attribute and attribute[
                'type'] in self.TYPES_TO_IMPORT:
                context = {
                    'id':
                        attribute['event_id'],
                    'link':
                        urljoin(
                            self.instances[instance]['url'],
                            '/events/{}'.format(
                                attribute['event_id'])),

                    'source':
                        self.instances[instance]['name'],

                    'comment':
                        attribute['comment']
                }

            try:
                klass = self.TYPES_TO_IMPORT[attribute['type']]
                obs = klass.get_or_create(value=attribute['value'])

                if attribute['category']:
                    obs.tag(attribute['category'].replace(' ', '_'))
                    obs.tag(tags)

                obs.add_context(context)
            except:
                logging.error(
                    "{}: error adding {}".format(
                        'MispFeed', attribute['value']))
