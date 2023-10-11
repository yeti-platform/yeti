from datetime import datetime
import logging

import requests
from dateutil import parser

from core.schemas import task
from core import taskmanager
from core.schemas.observable import ObservableType, Observable
from core.config.config import yeti_config
from core.schemas.observables import email, hostname, sha256
from core.schemas.entity import Company, Phone, Note
from core.schemas.entity import EntityTypes


def whois_links(observable: Observable, whois):
    to_extract = [
        {
            "field": "organization",
            "type": Company,
            "label": "Registrant Organization",
        },
        {
            "field": "registrar",
            "type": Company,
            "label": "Registrar",
        },
        {
            "field": "contactEmail",
            "type": email.Email,
            "label": "Registrant Email",
        },
        {
            "field": "name",
            "type": Company,
            "label": "Registrant Name",
        },
        {
            "field": "telephone",
            "type": Phone,
            "label": "Registrant Phone",
            "record_type": "phone",
        },
    ]

    for field in to_extract:
        if field["field"] in whois and whois[field["field"]] != "N/A":
            if field["Type"] == email.Email:
                obs = field["type"](value=whois[field["field"]]).save()
                observable.link_to(obs, field["label"], "PassiveTotal")
            else:
                ent = field["type"].get_or_create(name=whois[field["field"]])
                observable.link_to(ent, field["label"], "PassiveTotal")

    if "nameServers" in whois:
        for ns in whois["nameServers"]:
            if ns not in ["No nameserver", "not.defined"]:
                try:
                    ns_obs = hostname.Hostname(value=ns).save()
                    observable.link_to(ns_obs, "NS record", "PassiveTotal")
                except Exception as e:
                    logging.error(e.with_traceback())


class PassiveTotalApi(object):
    API_URL = "https://api.passivetotal.org/v2"

    @staticmethod
    def get(uri, params={}):
        url = PassiveTotalApi.API_URL + uri
        auth = (
            yeti_config.get("passivetotal", "username"),
            yeti_config.get("passivetotal", "api_key"),
        )

        response = requests.get(
            url, auth=auth, params=params, proxies=yeti_config.get('proxy')
        )
        response.raise_for_status()

        return response.json()


class PassiveTotalPassiveDNS(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Passive DNS",
        "description": "Perform passive DNS (reverse) lookups on domain names or IP addresses.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname, ObservableType.ipv4]

    def each(self, observable: Observable):
        params = {"query": observable.value}

        data = PassiveTotalApi.get("/dns/passive", params)
        context = {"source": "PassiveTotal Passive DNS"}
        for record in data["results"]:
            first_seen = datetime.strptime(record["firstSeen"], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(record["lastSeen"], "%Y-%m-%d %H:%M:%S")
            context["first_seen"] = first_seen
            context["last_seen"] = last_seen
            context["resolve"] = record["resolve"]
            try:
                new = Observable.add_text(record["resolve"]).save()
            except ValueError:
                logging.error(f"Could not add text observable for {record}")

            if observable.type is ObservableType.hostname:
                observable.link_to(
                    new, "{} record".format(record["recordType"]), "PassiveTotal"
                )

            else:
                new.link_to(
                    observable,
                    "{} record".format(record["recordType"]),
                    "PassiveTotal",
                )
            new.add_context("PassiveTotal", context)


class PassiveTotalMalware(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "Get Malware",
        "description": "Find malware related to domain names or IP addresses.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname, ObservableType.ipv4]

    def each(self, observable: Observable):
        params = {"query": observable.value}

        data = PassiveTotalApi.get("/enrichment/malware", params)

        for record in data["results"]:
            collection_date = parser.parse(record["collectionDate"])

            malware_obs = sha256.SHA256(value=record["sample"]).save()

            malware_obs.link_to(observable, "Contact to", "PassiveTotal")
            malware_obs.add_context(
                "PassiveTotal", {"collection_date": collection_date}
            )


class PassiveTotalSubdomains(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "Get Subdomains",
        "description": "Find all known subdomains.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        params = {"query": f"*.{observable.value}"}

        data = PassiveTotalApi.get("/enrichment/subdomains", params)

        for record in data["subdomains"]:
            subdomain = hostname.Hostname(value=f"{record}.{observable.value}").save()

            observable.link_to(subdomain, "Subdomain", "PassiveTotal")


class PassiveTotalWhois(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Whois",
        "description": "Get Whois information for a specific domain name.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        params = {
            "query": observable.value,
        }

        data = PassiveTotalApi.get("/whois", params)

        context = {"source": "PassiveTotal Whois", "raw": data}
        observable.add_context(context)

        whois_links(observable, data)


class PassiveTotalReverseWhois(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Reverse Whois",
        "description": "Find all known domain names for a specific whois field.",
    }

    acts_on: list[ObservableType] = [ObservableType.email]

    def each(self, observable: Observable):

        if observable.type is ObservableType.email:
            field = "email"
        elif observable.type:
            field = observable.type
        else:
            raise ValueError("Could not determine field for this observable")

        params = {"query": observable.value, "field": field}

        data = PassiveTotalApi.get("/whois/search", params)

        for record in data["results"]:
            domain = hostname.Hostname(value=record["domain"])
            whois_links(domain, record)


class PassiveTotalReverseNS(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Reverse NS",
        "description": "Find all known domain names for a specific NS server.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable):
        params = {"query": observable.value, "field": "nameserver"}

        data = PassiveTotalApi.get("/whois/search", params)

        for record in data["results"]:
            domain = hostname.Hostname(value=record["domain"]).save()
            whois_links(domain, record)


taskmanager.TaskManager.register_task(PassiveTotalPassiveDNS)
taskmanager.TaskManager.register_task(PassiveTotalMalware)
taskmanager.TaskManager.register_task(PassiveTotalSubdomains)
taskmanager.TaskManager.register_task(PassiveTotalWhois)
taskmanager.TaskManager.register_task(PassiveTotalReverseWhois)
taskmanager.TaskManager.register_task(PassiveTotalReverseNS)
