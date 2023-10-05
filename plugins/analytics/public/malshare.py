import json

import requests
import logging
from core.schemas import task
from core import taskmanager
from core.config.config import yeti_config
from core.schemas.observables import url, sha1, md5, sha256,ssdeep
from core.schemas.observable import ObservableType, Observable


class MalshareAPI(object):
    """Base class for querying the Malshare API.
    This is the public API, 1000 samples per day.

    Limit rejection, as it could cause api key deactivation.
    """

    @staticmethod
    def fetch(observable: Observable):
        """
        :param observable: The extended observable klass
        :param api_key: The api key obtained from Malshare
        :return:  malshare json response or None if error
        """

        try:
            params = {
                "hash": observable.value,
                "api_key": yeti_config["malshare"]["api_key"],
                "action": "details",
            }
            response = requests.get("https://malshare.com/api.php", params=params)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return
            else:
                raise RuntimeError(
                    f"Could not retrieve feed, HTTP response: {response.status_code}"
                )
        except:
            raise RuntimeError("Error Feeds")


class MalshareQuery(task.OneShotTask, MalshareAPI):
    _defaults = {
        "name": "MalShare",
        "description": "Perform a MalShare query.",
    }

    acts_on: list[ObservableType] = [
        ObservableType.sha1,
        ObservableType.sha256,
        ObservableType.md5,
    ]

    def each(self, observable: Observable):
        json_result = MalshareAPI.fetch(
            observable,
        )

        if json_result is None:
            return []

        context = {"source": "malshare.com"}
        logging.debug(json_result)
        if "SOURCES" in json_result:
            for source in json_result["SOURCES"]:
                new_url = None
                new_url = url.Url(value=source.strip()).save()
                observable.link_to(new_url, "c2", "malshare_query")

            context["nb C2"] = len(json_result["SOURCES"])
        if "FILENAMES" in json_result:
            context["filenames"] = " ".join(json_result["FILENAMES"])
        observable.add_context("malshare.com", context)

        new_hash = None
        if observable.type != ObservableType.md5:
            new_hash = md5.MD5(value=json_result["MD5"]).save()
            new_hash.add_context("malshare.com", context)
            new_hash.link_to(observable, "md5", "malshare_query")

        if observable.type != ObservableType.sha1:
            new_hash = sha1.SHA1(value=json_result["SHA1"]).save()

            new_hash.link_to(observable, "sha1", "malshare_query")

        if observable.type != ObservableType.sha256:
            new_hash = sha256.SHA256(value=json_result["SHA256"]).save()
            new_hash.link_to(observable, "sha256", "malshare_query")

        if new_hash:
            new_hash.add_context("malshare.com", context)
        
        if json_result["SSDEEP"]:
            ssdeep_data = ssdeep.SsdeepHash(value=json_result["SSDEEP"]).save()
            ssdeep_data.add_context("malshare.com", context)
            ssdeep_data.link_to(observable, "ssdeep", "malshare_query")


taskmanager.TaskManager.register_task(MalshareQuery)
