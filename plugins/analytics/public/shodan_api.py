import json
import logging
from core import taskmanager
from core.schemas.observable import Observable,ObservableType
from core.schemas.observables import ipv4,asn,hostname
from core.schemas.entity import Company
from core.schemas import task
from core.config.config import yeti_config
import shodan

class ShodanApi(object):
    settings = {
        "shodan_api_key": {
            "name": "Shodan API Key",
            "description": "API Key provided by Shodan.io.",
        }
    }

    
    def fetch(observable:Observable):
        try:
            return shodan.Shodan(yeti_config['shodan']['api_key']).host(observable.value)
        except shodan.APIError as e:
            logging.error("Error: {}".format(e))


class ShodanQuery(task.AnalyticsTask, ShodanApi):
    default_values = {
        "name": "Shodan",
        "description": "Perform a Shodan query on the IP address and tries to"
        " extract relevant information.",
    }

    acts_on: list[Observable] = [ObservableType.ip]

    def each(self,ip:ipv4.IPv4):
        result = ShodanApi.fetch(ip)

        if "tags" in result and result["tags"] is not None:
            ip.tag(result["tags"])

        if "asn" in result and result["asn"] is not None:
            o_asn = asn.ASN(
                value=result["asn"].replace("AS", "")
            )
            o_asn.link_to(ip, "asn#", "Shodan Query")

        if "hostnames" in result and result["hostnames"] is not None:
            for hostname_str in result["hostnames"]:
                h = hostname.Hostname(value=hostname_str)
                h.link_to(ip, "A record", "Shodan Query")

        if "isp" in result and result["isp"] is not None:
            o_isp = Company(name=result["isp"])
            ip.link_to(o_isp, "hosting", "Shodan Query")

taskmanager.TaskManager.register_task(ShodanQuery())
