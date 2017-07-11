import logging
import requests
from lxml import etree
from urlparse import urljoin
from mongoengine import DictField
from datetime import date, datetime, timedelta

from core.feed import Feed
from core.observables import Observable
from core.errors import ObservableValidationError
from core.config.config import yeti_config


class MispFeed(Feed):

    last_runs = DictField()

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "MispFeed",
        "description": "Parses events from a given MISP instance",
        "source": "MISP"
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

        orgs = requests.get(url, headers=headers).json()

        for org in orgs:
            org_id = org['Organisation']['id']
            org_name = org['Organisation']['name']
            self.instances[instance]['organisations'][org_id] = org_name

    def week_events(self, instance):
        one_week = timedelta(days=7)
        url = urljoin(self.instances[instance]['url'], '/events/xml/download.json')
        headers = {'Authorization': self.instances[instance]['key']}
        to = date.today()
        fromdate = to - timedelta(days=6)
        time_filter = {'request': {}}

        while True:
            imported = 0

            time_filter['request']['to'] = to.isoformat()
            time_filter['request']['from'] = fromdate.isoformat()
            r = requests.post(url, headers=headers, json=time_filter)

            try:
                msg = r.json()
                raise AttributeError(msg['message'])
            except ValueError:
                tree = etree.fromstring(r.content)

                for event in tree.findall(".//Event"):
                    self.analyze(event, instance)
                    imported += 1

                yield fromdate, to, imported
                to = to - one_week
                fromdate = fromdate - one_week

    def get_last_events(self, instance):
        print "Getting last events for {}".format(instance)
        last_run = self.last_run_for(instance)
        seen_last_run = False

        for date_from, date_to, imported in self.week_events(instance):
            print date_from, date_to

            if seen_last_run:
                break

            if date_from <= last_run <= date_to:
                seen_last_run = True

    def get_all_events(self, instance):
        print "Getting all events for {}".format(instance)
        had_results = True

        for date_from, date_to, imported in self.week_events(instance):
            print date_from, date_to

            if imported == 0:
                if had_results:
                    had_results = False
                else:
                    break
            else:
                had_results = True

    def update(self):
        for instance in self.instances:
            print "Processing instance {}".format(instance)
            self.get_organisations(instance)
            if instance in self.last_runs:
                self.get_last_events(instance)
            else:
                self.get_all_events(instance)

            self.modify(**{"set__last_runs__{}".format(instance): date.today().isoformat()})

    def analyze(self, event, instance):
        context = {}
        org = self.instances[instance]['organisations'][event.findtext('orgc_id')]
        context['org'] = org
        context['uuid'] = event.findtext('uuid')
        context['id'] = int(event.findtext('id'))
        context['link'] = urljoin(self.instances[instance]['url'], "/events/{}".format(context['id']))
        context['timestamp'] = datetime.fromtimestamp(float(event.findtext('timestamp')))
        context['source'] = self.instances[instance]['name']
        context['description'] = event.findtext('info')

        for attr in event.findall('Attribute'):
            type = attr.findtext('type')
            category = attr.findtext('category').replace(' ', '_')
            value = attr.findtext('value')
            context['comment'] = attr.findtext('comment') or "N/A"

            if type in ['domain', 'ip-dst', 'ip-src', 'url', 'hostname']:
                try:
                    obs = Observable.add_text(value)
                    if obs:
                        obs.tag(category)
                        obs.add_context(context)
                except ObservableValidationError:
                    logging.error("{}: error adding {}".format(self.__class__.name, value))
