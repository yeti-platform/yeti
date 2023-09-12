import logging
from datetime import date, timedelta, datetime
from urllib.parse import urljoin
import pandas as pd
from pymisp.api import PyMISP
from core.config.config import yeti_config
from core.schemas import observable
from core.schemas import task
from core import taskmanager

  
    
    

class MispFeed(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "MispFeed",
        "description": "Parses events from a given MISP instance",
        "source": "MISP",
    }

    _TYPES_TO_IMPORT = {
        "domain": observable.ObservableType.hostname,
        "hostname": observable.ObservableType.hostname,
        "ip-dst": observable.ObservableType.ip,
        "ip-src": observable.ObservableType.ip,
        "url": observable.ObservableType.url,
        "md5": observable.ObservableType.md5,
        "sha1": observable.ObservableType.sha1,
        "sha256": observable.ObservableType.sha256,
        "btc": observable.ObservableType.bitcoin_wallet,
        "email" : observable.ObservableType.email,
        "filename": observable.ObservableType.file,
        "regkey": observable.ObservableType.registry_key,
    }
        
    def get_instances(self):
        instances = {}
        for instance in yeti_config.get("misp", "instances", "").split(","):
            config = {
                "name": yeti_config.get(instance, "name") or instance,
                "galaxy_filter": yeti_config.get(instance, "galaxy_filter"),
                "days": yeti_config.get(instance, "days"),
                "organisations": {},
            }

            
            config["url"] = yeti_config.get(instance, "url")
            config["key"] = yeti_config.get(instance, "key")
            instances[instance] = config
           
        return instances

    
    def get_organisations(self,instance:dict):
        
            misp_client = PyMISP(
                url=instance["url"], key=instance["key"]
            )

            if not misp_client:
                logging.error("Issue on misp client")
                return

            orgs = misp_client.organisations(scope="all")
            for org in orgs:
                org_id = org["Organisation"]["id"]
                org_name = org["Organisation"]["name"]
                instance["organisations"][org_id] = org_name
       
    
    def get_all_events(self,instance:dict):
        days = None

        if "days" in instance:
            days = instance["days"]

        if not days:
            days = 60

        today = date.today()
        start_date = today - timedelta(days=days)

        weeks = self.decompose_weeks(start_date, today)
        for from_date,to_date in weeks:
            for event in self.get_event(instance, from_date, to_date):
                self.analyze(event, instance)

    def get_last_events(self, instance:dict):
        from_date = self.last_run
        logging.debug(f"Getting events from {from_date} and {self.last_run}")
        for event in self.get_event(instance, from_date):
            self.analyze(event, instance)

    def get_event(self, instance, from_date, to_date=None):
  
        misp_client = PyMISP(
            url=instance["url"], key=instance["key"]
        )
        from_date = from_date.strftime("%Y-%m-%d")
        if to_date:
            to_date = to_date.strftime("%Y-%m-%d")
        results = misp_client.search(date_from=from_date, date_to=to_date)
        logging.debug("Found {} events".format(len(results)))
        for r in results:
            if "Event" in r:
                yield r["Event"]

    def run(self):
        instances = self.get_instances()
        for instance_name, instance in instances.items():
            logging.debug("Processing instance {}".format(instance_name))
            self.get_organisations(instance)
            if self.last_run:
                self.get_last_events(instance)
            else:
                self.get_all_events(instance)

    def analyze(self, event, instance):
        tags = []
        galaxies_to_context = []

        context = {}
        context["date_added"] = datetime.utcnow()
        context["source"] = instance["name"]
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
            if not instance.get("galaxy_filter"):
                tags = [tag["name"] for tag in event["Tag"]]
            else:
                galaxies = instance["galaxy_filter"].split(",")

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

        if attribute.get("type") in self._TYPES_TO_IMPORT:
            context["id"] = attribute["event_id"]
            context["link"] = urljoin(
                instance["url"],
                "/events/{}".format(attribute["event_id"]),
            )

            context["comment"] = attribute["comment"]

            obs = observable.Observable.find(value=attribute["value"])
            if not obs:
                obs = observable.Observable.add_text(attribute['value'])

            if attribute["category"]:
                tags.append(attribute["category"])

            if tags:
                obs.tag(tags)

            obs.add_context(instance["name"], context)

    def decompose_weeks(self,start_day, last_day):
    
        # Génère la liste de tuples
        weeks = []
        current_start = start_day

        while current_start < last_day:
            current_end = current_start + timedelta(days=6)  # Jour suivant de 7 jours
            if current_end > last_day:
                current_end = last_day
            weeks.append((current_start, current_end))
            current_start += timedelta(days=7)  # Passe à la période de 7 jours suivante
        logging.debug(f"Decomposed weeks: {weeks}")
        return weeks

taskmanager.TaskManager.register_task(MispFeed)
