import logging
from datetime import datetime

import requests
from dateutil import parser

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import observable, task
from core.schemas.entity import Company, Phone
from core.schemas.observable import Observable, ObservableType
from core.schemas.observables import email, hostname, sha256


def whois_links(observable_obj: Observable, whois):
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
                observable_obj.link_to(obs, field["label"], "PassiveTotal")
            else:
                ent = field["type"].get_or_create(name=whois[field["field"]])
                observable_obj.link_to(ent, field["label"], "PassiveTotal")

    if "nameServers" in whois:
        for ns in whois["nameServers"]:
            if ns not in ["No nameserver", "not.defined"]:
                try:
                    ns_obs = hostname.Hostname(value=ns).save()
                    observable_obj.link_to(ns_obs, "NS record", "PassiveTotal")
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
            url, auth=auth, params=params, proxies=yeti_config.get("proxy")
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

    def each(self, observable_obj: Observable):
        params = {"query": observable_obj.value}

        data = PassiveTotalApi.get("/dns/passive", params)
        context = {"source": "PassiveTotal Passive DNS"}
        for record in data["results"]:
            first_seen = datetime.strptime(record["firstSeen"], "%Y-%m-%d %H:%M:%S")
            last_seen = datetime.strptime(record["lastSeen"], "%Y-%m-%d %H:%M:%S")
            context["first_seen"] = first_seen
            context["last_seen"] = last_seen
            context["resolve"] = record["resolve"]
            try:
                new = observable.save(value=record["resolve"])
            except ValueError:
                logging.error(f"Could not add text observable for {record}")

            if observable_obj.type is ObservableType.hostname:
                observable_obj.link_to(
                    new, "{} record".format(record["recordType"]), "PassiveTotal"
                )

            else:
                new.link_to(
                    observable_obj,
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

    def each(self, observable_obj: Observable):
        params = {"query": observable_obj.value}

        data = PassiveTotalApi.get("/enrichment/malware", params)

        for record in data["results"]:
            collection_date = parser.parse(record["collectionDate"])

            malware_obs = sha256.SHA256(value=record["sample"]).save()

            malware_obs.link_to(observable_obj, "Contact to", "PassiveTotal")
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

    def each(self, observable_obj: Observable):
        params = {"query": f"*.{observable_obj.value}"}

        data = PassiveTotalApi.get("/enrichment/subdomains", params)

        for record in data["subdomains"]:
            subdomain = hostname.Hostname(
                value=f"{record}.{observable_obj.value}"
            ).save()

            observable_obj.link_to(subdomain, "Subdomain", "PassiveTotal")


class PassiveTotalWhois(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Whois",
        "description": "Get Whois information for a specific domain name.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable_obj: Observable):
        params = {
            "query": observable_obj.value,
        }

        data = PassiveTotalApi.get("/whois", params)

        context = {"source": "PassiveTotal Whois", "raw": data}
        observable_obj.add_context(context)

        whois_links(observable_obj, data)


class PassiveTotalReverseWhois(task.OneShotTask, PassiveTotalApi):
    _defaults = {
        "group": "PassiveTotal",
        "name": "PassiveTotal Reverse Whois",
        "description": "Find all known domain names for a specific whois field.",
    }

    acts_on: list[ObservableType] = [ObservableType.email]

    def each(self, observable_obj: Observable):
        if observable_obj.type is ObservableType.email:
            field = "email"
        elif observable_obj.type:
            field = observable_obj.type
        else:
            raise ValueError("Could not determine field for this observable")

        params = {"query": observable_obj.value, "field": field}

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

    def each(self, observable_obj):
        params = {"query": observable_obj.value, "field": "nameserver"}

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
