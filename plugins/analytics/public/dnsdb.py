import requests
import json
from datetime import datetime

from core.schemas import task
from core import taskmanager
from core.config.config import yeti_config
from core.schemas.observable import ObservableType, Observable
from core.schemas.observables import hostname, ipv4

from core.config.config import yeti_config


class DNSDBApi(object):

    API_URL = "https://api.dnsdb.info/lookup"
    RECORD_TYPES = ["A", "CNAME", "NS"]

    @staticmethod
    def rdata_lookup(observable):
        links = set()

        for record in DNSDBApi.lookup("rdata", observable):
            new = Observable.add_text(record["rrname"]).save()
            new.link_to(
                observable,
                source="DNSDB Passive DNS",
                description=f"{record['rrtype']} record",
            )

    @staticmethod
    def rrset_lookup(hostname: hostname.Hostname):

        for record in DNSDBApi.lookup("rrset", hostname):
            for observable in record["rdata"]:
                observable = Observable.add_text(observable).save()

                hostname.link_to(
                    observable,
                    source="DNSDB Passive DNS",
                    description=f"{record['rrtype']} record",
                )

    @staticmethod
    def lookup(type, observable: Observable):
        headers = {
            "accept": "application/json",
            "X-Api-Key": yeti_config.get("dnsdb", "api_key"),
        }

        if observable.type == ObservableType.hostname:
            obs_type = "name"
        else:
            obs_type = "ip"

        url = f"{DNSDBApi.API_URL}/{type}/{obs_type}/{observable.value}"

        r = requests.get(url, headers=headers, proxies=yeti_config.proxy)

        if r.status_code == 200:
            records = []
            for record in r.iter_lines():
                record = json.loads(record)
                if record["rrtype"] in DNSDBApi.RECORD_TYPES:
                    if "time_first" in record:
                        record["first_seen"] = datetime.utcfromtimestamp(
                            record["time_first"]
                        )
                        record["last_seen"] = datetime.utcfromtimestamp(
                            record["time_last"]
                        )
                    else:
                        record["first_seen"] = datetime.utcfromtimestamp(
                            record["zone_time_first"]
                        )
                        record["last_seen"] = datetime.utcfromtimestamp(
                            record["zone_time_last"]
                        )

                    records.append(record)

            return records
        elif r.status_code == 404:
            return []
        else:
            r.raise_for_status()


class DNSDBReversePassiveDns(task.AnalyticsTask, DNSDBApi):
    default_values = {
        "group": "DNSDB",
        "name": "Reverse Passive DNS",
        "description": "Perform passive DNS reverse lookups on domain names or IP addresses.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname, ObservableType.ipv4]

    def each(self, observable):
        return DNSDBApi.rdata_lookup(observable)


class DNSDBPassiveDns(task.AnalyticsTask, DNSDBApi):
    _defaults = {
        "group": "DNSDB",
        "name": "DNSDB Passive DNS",
        "description": "Perform passive DNS lookups on domain names.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, hostname: hostname.Hostname):
        return DNSDBApi.rrset_lookup(hostname)


taskmanager.TaskManager.register_task(DNSDBPassiveDns)
taskmanager.TaskManager.register_task(DNSDBReversePassiveDns)
