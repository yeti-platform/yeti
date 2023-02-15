import datetime
import json
import logging

import requests

from core.analytics import OneShotAnalytics
from core.errors import ObservableValidationError
from core.observables import Hostname, Email, Ip, Hash


class ThreatCrowdAPI(object):
    """Base class for querying the ThreatCrowd API."""

    @staticmethod
    def fetch(observable):
        base_url_api = "https://www.threatcrowd.org/searchApi/v2"
        if isinstance(observable, Hostname):
            url = base_url_api + "/domain/report/"
            params = {"domain": observable.value}
            try:
                res = requests.get(url, params)

                if res.ok:
                    return res.json()
            except Exception as e:
                print("Exception while getting domain report {}".format(e.message))
                return None

        elif isinstance(observable, Email):
            url = base_url_api + "/email/report/"
            params = {"email": observable.value}
            try:
                res = requests.get(url, params)

                if res.ok:
                    return res.json()
            except Exception as e:
                print("Exception while getting email report {}".format(e.message))
                return None
        elif isinstance(observable, Ip):
            url = base_url_api + "/ip/report/"
            print(url)
            params = {"ip": observable.value}
            print(params)
            try:
                res = requests.get(url, params)

                if res.ok:
                    return res.json()
            except Exception as e:
                print("Exception while getting email report {}".format(e.message))
                return None
        elif isinstance(observable, Hash):
            url = base_url_api + "/file/report/"
            params = {"resource": observable.value}
            try:
                res = requests.get(url, params)

                if res.ok:
                    return res.json()
            except Exception as e:
                print("Exception while getting email report {}".format(e.message))
                return None


class ThreatCrowdQuery(ThreatCrowdAPI, OneShotAnalytics):
    default_values = {
        "name": "ThreatCrowd",
        "description": "Perform a ThreatCrowd query.",
    }

    ACTS_ON = ["Ip", "Hostname", "Hash", "Email"]

    @staticmethod
    def analyze(observable, results):
        links = set()
        json_result = ThreatCrowdAPI.fetch(observable)
        json_string = json.dumps(
            json_result, sort_keys=True, indent=4, separators=(",", ": ")
        )
        results.update(raw=json_string)
        result = {}
        if isinstance(observable, Hostname):
            if "resolutions" in json_result:
                result["ip on this domains"] = 0

                for ip in json_result["resolutions"]:
                    if ip["ip_address"].strip() != observable.value:
                        if ip["last_resolved"] != "0000-00-00":
                            last_resolved = datetime.datetime.strptime(
                                ip["last_resolved"], "%Y-%m-%d"
                            )
                            try:
                                new_ip = Ip.get_or_create(
                                    value=ip["ip_address"].strip()
                                )
                                links.update(
                                    new_ip.active_link_to(
                                        observable, "IP", "ThreatCrowd", last_resolved
                                    )
                                )
                                result["ip on this domains"] += 1
                            except ObservableValidationError:
                                logging.error(
                                    "An error occurred when trying to add subdomain {} to the database".format(
                                        ip["ip_address"]
                                    )
                                )

            if "emails" in json_result:
                result["nb emails"] = 0

                for email in json_result["emails"]:
                    try:
                        new_email = Email.get_or_create(value=email)
                        links.update(
                            new_email.active_link_to(
                                observable, "Used by", "ThreatCrowd"
                            )
                        )
                        result["nb emails"] += 1
                    except ObservableValidationError:
                        logging.error(
                            "An error occurred when trying to add email {} to the database".format(
                                email
                            )
                        )

            if "subdomains" in json_result:
                result["nb subdomains"] = 0

                for subdomain in json_result["subdomains"]:
                    try:
                        new_domain = Hostname.get_or_create(value=subdomain)
                        links.update(
                            observable.active_link_to(
                                new_domain, "subdomain", "ThreatCrowd"
                            )
                        )
                        result["nb subdomains"] += 1
                    except ObservableValidationError:
                        logging.error(
                            "An error occurred when trying to add subdomain {} to the database".format(
                                subdomain
                            )
                        )

        if isinstance(observable, Ip):
            if "resolutions" in json_result:
                result["domains resolved"] = 0

                for domain in json_result["resolutions"]:
                    if domain["domain"].strip() != observable.value:
                        try:
                            last_resolved = datetime.datetime.strptime(
                                domain["last_resolved"], "%Y-%m-%d"
                            )
                            new_domain = Hostname.get_or_create(
                                value=domain["domain"].strip()
                            )
                            links.update(
                                new_domain.active_link_to(
                                    observable, "A Record", "ThreatCrowd", last_resolved
                                )
                            )
                            result["domains resolved"] += 1
                        except ObservableValidationError:
                            logging.error(
                                "An error occurred when trying to add domain {} to the database".format(
                                    domain["domain"]
                                )
                            )

            if "hashes" in json_result and len(json_result["hashes"]) > 0:
                result["malwares"] = 0
                for h in json_result["hashes"]:
                    new_hash = Hash.get_or_create(value=h)
                    links.update(
                        new_hash.active_link_to(observable, "hash", "ThreatCrowd")
                    )
                    result["malwares"] += 1

        if isinstance(observable, Email):
            if "domains" in json_result and len(json_result) > 0:
                result["domains recorded by email"] = 0
                for domain in json_result["domains"]:
                    new_domain = Hostname.get_or_create(value=domain)
                    links.update(
                        new_domain.active_link_to(
                            observable, "recorded by", "ThreatCrowd"
                        )
                    )
                    result["domains recorded by email"] += 1

        if isinstance(observable, Hash):
            result["nb c2"] = 0

            if "md5" in json_result:
                new_hash = Hash.get_or_create(value=json_result["md5"])
                links.update(new_hash.active_link_to(observable, "md5", "ThreadCrowd"))

            if "sha1" in json_result:
                new_hash = Hash.get_or_create(value=json_result["sha1"])
                links.update(new_hash.active_link_to(observable, "sha1", "ThreadCrowd"))

            if "sha256" in json_result:
                new_hash = Hash.get_or_create(value=json_result["sha256"])
                links.update(
                    new_hash.active_link_to(observable, "sha256", "ThreadCrowd")
                )

            if "domains" in json_result and len(json_result["domains"]):
                for domain in json_result["domains"]:
                    new_domain = Hostname.get_or_create(value=domain)
                    links.update(
                        observable.active_link_to(new_domain, "c2", "ThreatCrowd")
                    )
                    result["nb c2"] += 1

            if "ips" in json_result and len(json_result["ips"]):
                for ip in json_result["ips"]:
                    new_ip = Ip.get_or_create(value=ip.strip())
                    links.update(observable.active_link_to(new_ip, "c2", "ThreatCrowd"))
                    result["nb c2"] += 1

        if "permalink" in json_result:
            result["permalink"] = json_result["permalink"]

        result["source"] = "threatcrowd_query"
        result["raw"] = json_string
        observable.add_context(result)
        return list(links)
