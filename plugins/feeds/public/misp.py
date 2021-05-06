import logging
from datetime import date, timedelta
from urllib.parse import urljoin

import requests
from mongoengine import DictField

from core.config.config import yeti_config
from core.feed import Feed
from core.observables import Ip, Url, Hostname, Hash, Email, Bitcoin, Observable
import pymisp
import pandas as pd


class MispFeed(Feed):
    last_runs = DictField()

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "MispFeed",
        "description": "Parses events from a given MISP instance",
        "source": "MISP",
    }

    TYPES_TO_IMPORT = {
        "domain": Hostname,
        "ip-dst": Ip,
        "ip-src": Ip,
        "url": Url,
        "hostname": Hostname,
        "md5": Hash,
        "sha1": Hash,
        "sha256": Hash,
        "btc": Bitcoin,
        "email-src": Email,
        "email-dst": Email,
    }

    def __init__(self, *args, **kwargs):
        super(MispFeed, self).__init__(*args, **kwargs)
        self.get_instances()

    def get_instances(self):
        self.instances = {}

        for instance in yeti_config.get("misp", "instances", "").split(","):
            config = {
                "name": yeti_config.get(instance, "name") or instance,
                "galaxy_filter": yeti_config.get(instance, "galaxy_filter"),
                "days": yeti_config.get(instance, "days"),
                "organisations": {},
            }

            try:
                url = yeti_config.get(instance, "url")
                key = yeti_config.get(instance, "key")
                misp_client = pymisp.PyMISP(url=url, key=key)
                config["misp_client"] = misp_client
                self.instances[instance] = config
            except Exception as e:
                logging.error("Error Misp connection %s" % e)

    def last_run_for(self, instance):
        last_run = [int(part) for part in self.last_runs[instance].split("-")]

        return date(*last_run)

    def get_organisations(self, instance):
        try:
            misp_client = self.__get_info_instance(instance, "misp_client")

            if not misp_client:
                logging.error("Issue on misp client")
                return

            orgs = misp_client.organisations(scope="all")
            for org in orgs:
                org_id = org["Organisation"]["id"]
                org_name = org["Organisation"]["name"]
                self.instances[instance]["organisations"][org_id] = org_name
        except Exception as e:
            logging.error("error http %s to get instances" % e)

    def get_all_events(self, instance):
        days = self.__get_info_instance(instance, "days")
        if not days:
            days = 60

        today = date.today()
        start_date = today - timedelta(days=days)

        range_time = [str(r) for r in pd.date_range(start_date, today, periods=7)]
        for i in range(0, len(range_time) - 1, 2):
            from_date = range_time[i]
            to_date = range_time[i + 1]
            for event in self.get_event(instance, from_date, to_date):
                self.analyze(event, instance)

    def get_last_events(self, instance):
        misp_client = self.__get_info_instance(instance, "misp_client")

        from_date = self.last_run
        for event in self.get_event(instance, from_date):
            self.analyze(event, instance)

    def get_event(self, instance, from_date, to_date=None):
        misp_client = self.__get_info_instance(instance, "misp_client")
        results = misp_client.search(fromdate=from_date, todate=to_date)
        for r in results:
            if "Event" in r:
                yield r["Event"]

    def update(self):
        for instance in self.instances:
            logging.debug("Processing instance {}".format(instance))
            self.get_organisations(instance)
            if instance in self.last_runs:
                self.get_last_events(instance)
            else:
                self.get_all_events(instance)

            self.modify(
                **{"set__last_runs__{}".format(instance): date.today().isoformat()}
            )

    def analyze(self, event, instance):
        tags = []
        galaxies_to_context = []

        context = {}
        context["source"] = self.__get_info_instance(instance, "name")
        external_analysis = [
            attr["value"]
            for attr in event["Attribute"]
            if attr["category"] == "External analysis"
            and attr["type"] == "url"
            and attr["to_ids"]
        ]
        if external_analysis:
            context["external sources"] = "\r\n".join(external_analysis)
        if "Tag" in event:
            if not self.instances[instance].get("galaxy_filter"):
                tags = [tag["name"] for tag in event["Tag"]]
            else:
                galaxies = self.instances[instance]["galaxy_filter"].split(",")

                for tag in event["Tag"]:
                    found = False
                    if "misp-galaxy" in tag["name"]:
                        galaxies_to_context.append(tag["name"])
                    for g in galaxies:
                        if g in tag["name"]:
                            found = True
                            break
                    if not found:
                        tags.append(tag["name"])

        for attribute in event["Attribute"]:
            self.__add_attribute(instance, attribute, context, tags)

        for obj in event["Object"]:
            for attribute in obj["Attribute"]:
                self.__add_attribute(instance, attribute, context, tags)

    def __add_attribute(self, instance, attribute, context, tags):

        if attribute["category"] == "External analysis":
            return

        if attribute.get("type") in self.TYPES_TO_IMPORT:

            context["id"] = attribute["event_id"]
            context["link"] = urljoin(
                self.__get_info_instance(instance, "misp_client").root_url,
                "/events/{}".format(attribute["event_id"]),
            )

            context["comment"] = attribute["comment"]

            obs = Observable.add_text(attribute["value"])

            if attribute["category"]:
                obs.tag(attribute["category"].replace(" ", "_"))

            if tags:
                obs.tag(tags)

            obs.add_context(context)

    def __get_info_instance(self, instance, key):
        if instance in self.instances:
            if key in self.instances[instance]:
                return self.instances[instance][key]
