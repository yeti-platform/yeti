import logging
import re
from datetime import timedelta
from typing import ClassVar

import requests

from core import taskmanager
from core.schemas import task
from core.schemas.observable import Observable
from core.schemas.observables import url


class MiningPoolStats(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "MiningPoolStats",
        "description": "This feed contains cryptomoining pools urls",
    }

    _SOURCE: ClassVar["str"] = "https://miningpoolstats.stream"
    _USER_AGENT: ClassVar[
        "str"
    ] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def run(self):
        data = {"query": "get_recent", "selector": "time"}
        coin_names = self._get_coin_names()
        if not coin_names:
            return False
        total = len(coin_names)
        logging.info(f"Found {total} coin names")
        count = 1
        for coin_name in coin_names:
            logging.info(f"Processing {coin_name} ({count}/{total})")
            count += 1
            tags = ["cryptomining", "cryptominer", "cryptomining-pool", coin_name]
            for data in self._extract_pool_urls(coin_name):
                url_value = data.get("url", "").strip()
                url_obs = None
                if url_value:
                    url_obs = url.Url(value=url_value).save()
                    url_obs.tag(tags)
                    url_obs.add_context(self.name, {"source": self.name})
                pool_id = data.get("pool_id", "").strip()
                if pool_id:
                    # some pool_id are not valid ipv4 or hostname, ex: superblockchain
                    try:
                        obs = Observable.add_text(pool_id, tags)
                        obs.add_context(self.name, {"source": self.name})
                    except Exception as err:
                        logging.error(f"Can't add {pool_id} as observable - {err}")
        return True

    def _extract_pool_urls(self, coin_name):
        endpoint = f"{self._SOURCE}/{coin_name}"
        headers = {"User-Agent": self._USER_AGENT}
        response = requests.get(endpoint, headers=headers)
        if response.status_code != 200:
            logging.debug(
                f"Can't fetch coin page {coin_name} - code: {response.status_code}, reason: {response.reason}"
            )
            return
        pattern = (
            r'href="(https://data.miningpoolstats.stream/data/'
            + coin_name
            + r'.js\?t=[0-9]{10})"'
        )
        m = re.search(pattern, response.text)
        if not m:
            logging.debug("Can't find pools endpoint")
            return
        response = requests.get(m.group(1), headers=headers)
        if response.status_code != 200:
            logging.debug(
                f"Can't fetch pool page - code: {response.status_code}, reason: {response.reason}"
            )
            return
        for data in response.json().get("data", []):
            yield data
        return

    def _get_coin_names(self):
        coin_names = set()
        headers = {"User-Agent": self._USER_AGENT}
        response = requests.get("https://miningpoolstats.stream", headers=headers)
        if response.status_code != 200:
            logging.debug(
                f"Can't fetch main page - code: {response.status_code}, reason: {response.reason}"
            )
            return None
        m = re.search(
            r'href="(https://data.miningpoolstats.stream/data/coins_data.js\?t=[0-9]{10})"',
            response.text,
        )
        if not m:
            logging.debug("Can't extract pages from response")
            return None
        response = requests.get(m.group(1), headers=headers)
        if response.status_code != 200:
            logging.debug(
                f"Can't fetch data - code: {response.status_code}, reason: {response.reason}"
            )
            return None
        for data in response.json().get("data", []):
            coin_names.add(data.get("page"))
        return coin_names


taskmanager.TaskManager.register_task(MiningPoolStats)
