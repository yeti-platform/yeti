import json

import logging
from core import taskmanager
from core.schemas.observable import Observable, ObservableType, TYPE_MAPPING
from core.schemas.observables import ipv4, asn, hostname, sha256, url
from core.schemas import task
from core.config.config import yeti_config
from datetime import datetime
import requests


class VirustotalApi(object):
    """Base class for querying the VirusTotal API.
    This is the public API, so there is a limit for up to 3
    requests per minute.

    TODO: Register a redis key with the last query time and prevent
    limit rejection, as it could cause api key deactivation.
    """

    @staticmethod
    def fetch(endpoint):
        """
        :param observable: The extended observable klass
        :param api_key: The api key obtained from VirusTotal
        :param endpoint: endpoint VT API
        :return:  virustotal json response or None if error
        """
        try:
            response = None
            base_url = "https://www.virustotal.com/api/v3"
            url = base_url + endpoint
            header = {"x-apikey": yeti_config.get("virustotal", "api_key")}
            response = requests.get(url, headers=header, proxies=yeti_config.get('proxy'))

            if response.ok:
                return response.json()
            else:
                return None
        except Exception as e:
            logging.error("Exception while getting ip report {}".format(e.message))
            return None

    @staticmethod
    def process_domain(domain: hostname.Hostname, attributes):
        context = {"source": "VirusTotal"}
        logging.debug(attributes)
        context["whois"] = attributes["whois"]
        if "whois_date" in attributes:
            timestamp_whois_date = attributes["whois_date"]
            context["whois_date"] = datetime.fromtimestamp(
                timestamp_whois_date
            ).isoformat()
        if "last_dns_records" in attributes:
            last_dns_records = attributes["last_dns_records"]

            for rr in last_dns_records:
                related_obs = None
                if rr["type"] == "A":
                    related_obs = ipv4.IPv4(value=rr["value"]).save()
                elif rr["type"] == "MX":
                    related_obs = hostname.Hostname(value=rr["value"]).save()
                elif rr["type"] == "SOA":
                    related_obs = hostname.Hostname(value=rr["value"]).save()
                elif rr["type"] == "NS":
                    related_obs = hostname.Hostname(value=rr["value"]).save()
                if related_obs:
                    related_obs.link_to(domain, rr["type"], context["source"])

        if "last_dns_records_date" in attributes:
            timestamp_lst_dns_record = attributes["last_dns_records_date"]
            context["last_dns_records_date"] = datetime.fromtimestamp(
                timestamp_lst_dns_record
            ).isoformat()
        if "registrar" in attributes:
            context["registrar"] = attributes["registrar"]

        tags = attributes["tags"]
        if tags:
            domain.tag(tags)
        if "popularity_ranks" in attributes:
            populary_rank = attributes["popularity_ranks"]
            for k, v in populary_rank.items():
                context[k] = v
        if "last_analysis_stats" in attributes:
            stats_analysis = attributes["last_analysis_stats"]

            for k, v in stats_analysis.items():
                context[k] = v
        if "last_https_certificate" and "last_https_certificate_date" in attributes:
            context["last_https_certificate"] = attributes["last_https_certificate"]
            try:
                timestamp_https_cert = attributes["last_https_certificate_date"]
                context["last_https_certificate_date"] = datetime.fromtimestamp(
                    timestamp_https_cert
                ).isoformat()

            except TypeError or ValueError:
                pass

        domain.add_context("VirusTotal", context)

    @staticmethod
    def process_file(file_vt: Observable, attributes):
        context = {"source": "VirusTotal"}

        stat_files = attributes["last_analysis_stats"]

        for k, v in stat_files.items():
            context[k] = v

        context["magic"] = attributes["magic"]
        first_seen = attributes["first_submission_date"]

        context["first_seen"] = datetime.fromtimestamp(first_seen).isoformat()

        last_seen = attributes["last_analysis_date"]
        context["last_seen"] = datetime.fromtimestamp(last_seen).isoformat()
        context["names"] = " ".join(n for n in attributes["names"])
        tags = attributes["tags"]
        if attributes["last_analysis_results"]:
            context["raw"] = attributes["last_analysis_results"]
        if tags:
            file_vt.tag(tags)
        observables = [
            (h, TYPE_MAPPING[h](value=attributes[h], type=h).save())
            for h in (ObservableType.sha256, ObservableType.sha1, ObservableType.md5)
            if file_vt.value != attributes[h]
        ]
        for h, obs in observables:
            obs.add_context("Virustotal", context)
            obs.link_to(file_vt, h, "Virustotal")
            obs.tag(tags)

        file_vt.add_context("VirusTotal", context)


class VTFileIPContacted(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT IP Contacted",
        "description": "Perform a Virustotal query to contacted domains by a file.",
    }

    acts_on: list[ObservableType] = [
        ObservableType.sha256,
        ObservableType.md5,
        ObservableType.sha1,
    ]

    def each(self, observable: Observable):
        context = {"source": "VirusTotal"}

        endpoint = "/files/%s/contacted_ips" % observable.value
        result = VirustotalApi.fetch(endpoint)
        if result:
            for data in result["data"]:
                ip = ipv4.IPv4(value=data["id"]).save()

                attributes = data["attributes"]

                context["whois"] = attributes["whois"]
                whois_timestamp = attributes["whois_date"]
                whois_date = datetime.fromtimestamp(whois_timestamp).isoformat()
                context["whois_date"] = whois_date

                context["country"] = attributes["country"]
                asn_obs = asn.ASN(value=str(attributes["asn"])).save()
                ip.link_to(asn_obs, "ASN", context["source"])

                context["as_owner"] = attributes["as_owner"]
                if "last_https_certificate" in attributes:
                    context["last_https_certificate"] = json.dumps(
                        attributes["last_https_certificate"]
                    )

                stat_files = attributes["last_analysis_stats"]

                for k, v in stat_files.items():
                    context[k] = v

                ip.add_context("VirusTotal", context)

                ip.link_to(observable, "contacted by", context["source"])


class VTFileUrlContacted(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Urls Contacted",
        "description": "Perform a Virustotal query to contacted domains by a file.",
    }

    acts_on: list[ObservableType] = [
        ObservableType.sha256,
        ObservableType.md5,
        ObservableType.sha1,
    ]

    def each(self, observable: Observable):
        context = {"source": "VirusTotal"}

        endpoint = "/files/%s/contacted_urls" % observable.value

        result = VirustotalApi.fetch(endpoint)
        if result:
            for data in result["data"]:
                if "attributes" in data:
                    attributes = data["attributes"]

                    timestamp_first_submit = attributes["first_submission_date"]
                    context["first_seen"] = datetime.fromtimestamp(
                        timestamp_first_submit
                    ).isoformat()

                    url_obs = url.Url(value=attributes["url"]).save()
                    url_obs.link_to(observable, "contacted by", context["source"])

                    if "last_http_response_code" in attributes:
                        context["last_http_response_code"] = str(
                            attributes["last_http_response_code"]
                        )
                    if "last_http_response_content_length" in attributes:
                        context["last_http_response_content_length"] = str(
                            attributes["last_http_response_content_length"]
                        )

                    timestamp_last_modif = attributes["last_modification_date"]
                    context["last_modification_date"] = datetime.fromtimestamp(
                        timestamp_last_modif
                    ).isoformat()

                    timestamp_last_analysis = attributes["last_analysis_date"]
                    context["last_analysis_date"] = datetime.fromtimestamp(
                        timestamp_last_analysis
                    ).isoformat()

                    stat_files = data["attributes"]["last_analysis_stats"]
                    for k, v in stat_files.items():
                        context[k] = v
                    tags = attributes["tags"]
                    if tags:
                        url_obs.tag(tags)
                    url_obs.add_context("VirusTotal", context)


class VTDomainContacted(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Domain Contacted",
        "description": "Perform a Virustotal query to contacted domains by a file.",
    }

    acts_on: list[ObservableType] = [
        ObservableType.sha256,
        ObservableType.md5,
        ObservableType.sha1,
    ]

    def each(self, observable):
        context = {"source": "VirusTotal"}

        endpoint = "/files/%s/contacted_domains" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            for data in result["data"]:
                hostname_obs = hostname.Hostname(value=data["id"]).save()
                context["first_seen"] = data["attributes"]["creation_date"]
                stat_files = data["attributes"]["last_analysis_stats"]
                context["registrar"] = data["attributes"]["registrar"]
                context["whois"] = data["attributes"]["whois"]
                for k, v in stat_files.items():
                    context[k] = v
                hostname_obs.link_to(observable, "contacted by", context["source"])
                hostname_obs.add_context("VirusTotal", context)


class VTFileReport(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Hash Report",
        "description": "Perform a Virustotal query to have a report.",
    }

    acts_on: list[ObservableType] = [
        ObservableType.sha256,
        ObservableType.md5,
        ObservableType.sha1,
    ]

    def each(self, observable: Observable):
        context = {"source": "VirusTotal"}

        endpoint = "/files/%s" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            VirustotalApi.process_file(observable, result["data"]["attributes"])


class VTDomainReport(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Domain Report",
        "description": "Perform a Virustotal query to have a report.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        endpoint = "/domains/%s" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            attributes = result["data"]["attributes"]
            VirustotalApi.process_domain(observable, attributes)


class VTDomainResolution(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Domain Resolution",
        "description": "Perform a Virustotal query to have PDNS results.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        context = {"source": "VirusTotal PDNS"}

        endpoint = "/domains/%s/resolutions" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            for data in result["data"]:
                attribute = data["attributes"]
                ip_address = attribute["ip_address"]
                ip = ipv4.IPv4(value=ip_address).save()
                ip.link_to(observable, "resolved", context["source"])
                timestamp_resolv = attribute["date"]
                date_last_resolv = datetime.fromtimestamp(timestamp_resolv).isoformat()
                context[ip_address] = date_last_resolv

                ip.add_context(
                    "Virustotal",
                    {"source": context["source"], observable.value: date_last_resolv},
                )

            observable.add_context("VirusTotal", context)


class VTSubdomains(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Subdomains",
        "description": "Perform a Virustotal query to have subdomains.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):

        endpoint = "/domains/%s/subdomains" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            for data in result["data"]:
                context = {"source": "VirusTotal"}
                attributes = data["attributes"]
                sub_domain = hostname.Hostname(value=data["id"]).save()
                VirustotalApi.process_domain(sub_domain, attributes)

                sub_domain.link_to(observable, "Subdomain", "Virustotal")


class VTDomainComFile(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Com files domain",
        "description": "Perform a Virustotal query to have files reffered.",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        links = set()
        endpoint = "/domains/%s/communicating_files" % observable.value
        result = VirustotalApi.fetch(endpoint)
        for data in result["data"]:
            attributes = data["attributes"]
            file_vt = sha256.SHA256(value=data["id"]).save()

            file_vt.link_to(observable, "communicating", "Virustotal")

            VirustotalApi.process_file(file_vt, attributes)


class VTDomainReferrerFile(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT Referrer files domain",
        "description": "Perform a query to have files refferer on the domain",
    }

    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        endpoint = "/domains/%s/referrer_files" % observable.value

        result = VirustotalApi.fetch(endpoint)
        for data in result["data"]:
            attributes = data["attributes"]
            file_vt = sha256.SHA256(value=data["id"]).save()
            file_vt.link_to(observable, "Referrer File", "Virustotal")
            VirustotalApi.process_file(file_vt, attributes)


class VTIPResolution(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT IP Resolution",
        "description": "Perform a query to have domains with PDNS.",
    }

    acts_on: list[ObservableType] = [ObservableType.ipv4]

    def each(self, observable: Observable):
        endpoint = "/ip_addresses/%s/resolutions" % observable.value

        result = VirustotalApi.fetch(endpoint)

        if result:
            for data in result["data"]:
                context = {"source": "VirusTotal PDNS"}
                attributes = data["attributes"]
                hostname_obs = hostname.Hostname(value=attributes["host_name"]).save()
                if "date" in attributes:
                    timestamp_date = attributes["date"]
                    date_last_resolv = datetime.fromtimestamp(
                        timestamp_date
                    ).isoformat()
                    context[hostname_obs.value] = date_last_resolv

                    hostname_obs.add_context(
                        "VirusTotal",
                        {
                            observable.value: date_last_resolv,
                        },
                    )

                    hostname_obs.link_to(observable, "resolved", context["source"])


class VTIPComFile(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT IP Com files",
        "description": "Perform a query to have files communicating on the IP ",
    }

    acts_on: list[ObservableType] = [ObservableType.ipv4]

    def each(self, observable: Observable):
        endpoint = "/ip_addresses/%s/communicating_files" % observable.value

        result = VirustotalApi.fetch(endpoint)

        for data in result["data"]:
            attributes = data["attributes"]
            file_vt = sha256.SHA256(value=data["id"]).save()

            file_vt.link_to(observable, "communicating", "Virustotal")

            VirustotalApi.process_file(file_vt, attributes)


class VTIPReferrerFile(task.OneShotTask, VirustotalApi):
    _defaults = {
        "group": "Virustotal",
        "name": "VT IP Referrer files",
        "description": "Perform a Virustotal query to have refferer files.",
    }

    acts_on: list[ObservableType] = [ObservableType.ipv4]

    def each(self, observable: Observable):
        endpoint = "/ip_addresses/%s/referrer_files" % observable.value

        result = VirustotalApi.fetch(endpoint)
        for data in result["data"]:
            attributes = data["attributes"]
            file_vt = sha256.SHA256(value=data["id"]).save()
            file_vt.link_to(observable, "Referrer File", "Virustotal")
            VirustotalApi.process_file(file_vt, attributes)


taskmanager.TaskManager.register_task(VTFileIPContacted)
taskmanager.TaskManager.register_task(VTFileUrlContacted)
taskmanager.TaskManager.register_task(VTDomainContacted)
taskmanager.TaskManager.register_task(VTFileReport)
taskmanager.TaskManager.register_task(VTDomainReport)
taskmanager.TaskManager.register_task(VTDomainResolution)
taskmanager.TaskManager.register_task(VTSubdomains)
taskmanager.TaskManager.register_task(VTDomainComFile)
taskmanager.TaskManager.register_task(VTDomainReferrerFile)
taskmanager.TaskManager.register_task(VTIPResolution)
taskmanager.TaskManager.register_task(VTIPComFile)
taskmanager.TaskManager.register_task(VTIPReferrerFile)
