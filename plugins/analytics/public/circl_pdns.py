import json
from datetime import datetime

import requests

from core.schemas import task
from core import taskmanager
from core.config.config import yeti_config
from core.schemas.observables import ipv4,hostname
from core.schemas.observable import Observable,ObservableType


class CirclPDNSApi(object):
    settings = {
        "circl_username": {
            "name": "Circl.lu username",
            "description": "Username for Circl.lu API.",
        },
        "circl_password": {
            "name": "Circl.lu password",
            "description": "Password for Circl.lu API.",
        },
    }

    def fetch(observable:Observable):
        auth = (CirclPDNSApi.settings["circl_username"], CirclPDNSApi.settings["circl_password"])
        API_URL = "https://www.circl.lu/pdns/query/"
        headers = {"accept": "application/json"}
        results = []
        r = requests.get(
            API_URL + observable.value,
            auth=auth,
            headers=headers,
            proxies=yeti_config.proxy,
        )
        if r.status_code == 200:
            for l in filter(None, r.text.split("\n")):
                obj = json.loads(l)
                results.append(obj)

        return results


class CirclPDNSApiQuery(task.AnalyticsTask, CirclPDNSApi):
    _defaults = {
        "name": "Circl.lu PDNS",
        "group": "PDNS",
        "description": "Perform passive DNS \
        lookups on domain names or ip address.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname,ObservableType.ip]

    def each(observable:Observable):
    
        json_result = CirclPDNSApi.fetch(observable, CirclPDNSApi.settings)

        result = {}
        result["source"] = "circl_pdns_query"
    
        if observable.type == ObservableType.ip:
            for record in json_result:
                new_hostname = hostname.Hostname(value=record['rrname'])
                observable.link_to(new_hostname,record['rrtype'],'Circl PDNS')
                
        elif observable.type == ObservableType.hostname:
            for record in json_result:
                new_ip = hostname.Hostname(value=record["rdata"])
                observable.link_to(new_ip,record['rrtype'],'Circl PDNS')
                
taskmanager.TaskManager.register_task(CirclPDNSApiQuery)
