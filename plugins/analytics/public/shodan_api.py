import logging
from core import taskmanager
from core.schemas.observable import Observable, ObservableType
from core.schemas.observables import ipv4, asn, hostname
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

    def fetch(observable: Observable):
        try:
            return shodan.Shodan(yeti_config.get("shodan", "api_key")).host(
                observable.value
            )
        except shodan.APIError as e:
            logging.error("Error: {}".format(e))


class ShodanQuery(task.OneShotTask, ShodanApi):
    _defaults = {
        "name": "Shodan",
        "description": "Perform a Shodan query on the IP address and tries to"
        " extract relevant information.",
    }

    acts_on: list[ObservableType] = [ObservableType.ipv4]

    def each(self, ip: ipv4.IPv4) -> Observable:

        result = ShodanApi.fetch(ip)
        logging.debug(result)

        if "tags" in result and result["tags"] is not None:
            ip.tag(result["tags"])

        logging.debug(result["asn"])
        if "asn" in result and result["asn"] is not None:
            o_asn = asn.ASN(
                value=result["asn"],
            ).save()
            logging.debug(o_asn)
            o_asn.link_to(ip, "asn#", "Shodan Query")

        if "hostnames" in result and result["hostnames"] is not None:
            for hostname_str in result["hostnames"]:
                h = hostname.Hostname(value=hostname_str).save()
                h.link_to(ip, "A record", "Shodan Query")

        if "isp" in result and result["isp"] is not None:
            logging.debug(result["isp"])
            o_isp = Company(name=result["isp"]).save()
            ip.link_to(o_isp, "hosting", "Shodan Query")
        return ip


taskmanager.TaskManager.register_task(ShodanQuery)
