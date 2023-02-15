import requests
import json
from datetime import datetime

from core.analytics import OneShotAnalytics
from core.observables import Observable, Hostname
from core.config.config import yeti_config


class DNSDBApi(object):
    settings = {
        "dnsdb_api_key": {
            "name": "DNSDB API Key",
            "description": "API Key provided by Farsight.",
        }
    }

    API_URL = "https://api.dnsdb.info/lookup"
    RECORD_TYPES = ["A", "CNAME", "NS"]

    @staticmethod
    def rdata_lookup(observable, api_key):
        links = set()

        for record in DNSDBApi.lookup("rdata", observable, api_key):
            new = Observable.add_text(record["rrname"])
            new.add_source("analytics")

            links.update(
                new.link_to(
                    observable,
                    source="DNSDB Passive DNS",
                    description="{} record".format(record["rrtype"]),
                    first_seen=record["first_seen"],
                    last_seen=record["last_seen"],
                )
            )

        return list(links)

    @staticmethod
    def rrset_lookup(hostname, api_key):
        links = set()

        for record in DNSDBApi.lookup("rrset", hostname, api_key):
            for observable in record["rdata"]:
                observable = Observable.add_text(observable)
                observable.add_source("analytics")

                links.update(
                    hostname.link_to(
                        observable,
                        source="DNSDB Passive DNS",
                        description="{} record".format(record["rrtype"]),
                        first_seen=record["first_seen"],
                        last_seen=record["last_seen"],
                    )
                )

        return list(links)

    @staticmethod
    def lookup(type, observable, api_key):
        headers = {"accept": "application/json", "X-Api-Key": api_key}

        if isinstance(observable, Hostname):
            obs_type = "name"
        else:
            obs_type = "ip"

        url = "{}/{}/{}/{}".format(DNSDBApi.API_URL, type, obs_type, observable.value)

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


class DNSDBReversePassiveDns(OneShotAnalytics, DNSDBApi):
    default_values = {
        "group": "DNSDB",
        "name": "Reverse Passive DNS",
        "description": "Perform passive DNS reverse lookups on domain names or IP addresses.",
    }

    ACTS_ON = ["Hostname", "Ip"]

    @staticmethod
    def analyze(observable, results):
        return DNSDBApi.rdata_lookup(observable, results.settings["dnsdb_api_key"])


class DNSDBPassiveDns(OneShotAnalytics, DNSDBApi):
    default_values = {
        "group": "DNSDB",
        "name": "DNSDB Passive DNS",
        "description": "Perform passive DNS lookups on domain names.",
    }

    ACTS_ON = "Hostname"

    @staticmethod
    def analyze(hostname, results):
        return DNSDBApi.rrset_lookup(hostname, results.settings["dnsdb_api_key"])
