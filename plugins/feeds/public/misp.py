import logging
import unicodedata
from datetime import date, datetime, timedelta
from urllib.parse import urljoin

from pymisp.api import PyMISP

from core import taskmanager
from core.common.misp_to_yeti import MISP_TYPES_TO_IMPORT
from core.config.config import yeti_config
from core.schemas import observable, task


class MispFeed(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "MispFeed",
        "description": "Parses events from a given MISP instance",
        "source": "MISP",
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
            config["verifycert"] = yeti_config.get(instance, "verifycert")
            instances[instance] = config

        return instances

    def get_organisations(self, instance: dict):
        misp_client = PyMISP(
            url=instance["url"], key=instance["key"], ssl=instance["verifycert"]
        )

        if not misp_client:
            logging.error("Issue on misp client")
            return

        orgs = misp_client.organisations(scope="all")
        for org in orgs:
            org_id = org["Organisation"]["id"]
            org_name = org["Organisation"]["name"]
            instance["organisations"][org_id] = org_name

    def get_all_events(self, instance: dict):
        days = None

        if "days" in instance:
            days = instance["days"]

        if not days:
            days = 60

        today = date.today()
        start_date = today - timedelta(days=days)

        weeks = self.decompose_weeks(start_date, today)
        for from_date, to_date in weeks:
            for event in self.get_event(instance, from_date, to_date):
                self.analyze(event, instance)

    def get_last_events(self, instance: dict):
        from_date = self.last_run
        logging.debug(f"Getting events from {from_date} and {self.last_run}")
        for event in self.get_event(instance, from_date):
            self.analyze(event, instance)

    def get_event(self, instance: dict, from_date: str, to_date: str = None):
        misp_client = PyMISP(
            url=instance["url"], key=instance["key"], ssl=instance["verifycert"]
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

    def analyze(self, event: dict, instance: dict):
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
            self._add_attribute(instance, attribute, context, tags)

        for obj in event["Object"]:
            for attribute in obj["Attribute"]:
                self._add_attribute(instance, attribute, context, tags)

    def _add_attribute(
        self, instance: dict, attribute: dict, context: dict, tags: list
    ):
        if attribute["category"] == "External analysis":
            return

        if attribute.get("type") in MISP_TYPES_TO_IMPORT:
            context["id"] = attribute["event_id"]
            context["link"] = urljoin(
                instance["url"],
                "/events/{}".format(attribute["event_id"]),
            )

            context["comment"] = attribute["comment"]

            obs = observable.Observable.add_text(attribute["value"])
            self._add_tag(obs, instance, attribute)
            if attribute["category"]:
                tags.append(attribute["category"])

            if tags:
                obs.tag(tags)

            obs.add_context(instance["name"], context)

    def decompose_weeks(self, start_day: datetime, last_day: datetime):
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

    def _add_tag(self, obs: observable.Observable, instance: dict, attribute: dict):
        instance_name = instance["name"].lower()
        nfkd_form = unicodedata.normalize("NFKD", instance_name)
        instance_name = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
        tag = f"{instance_name}:{attribute['event_id']}"
        obs.tag(tag)


taskmanager.TaskManager.register_task(MispFeed)
