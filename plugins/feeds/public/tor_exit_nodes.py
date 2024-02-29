from datetime import timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.observables import ipv4
from core.schemas.observables import hostname


class TorExitNodes(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=24),
        "name": "TorExitNodes",
        "description": "Tor exit nodes",
    }
    _SOURCE: ClassVar[str] = "https://onionoo.torproject.org/summary"

    def run(self):
        self._get_relays()
        return True

    def _get_relays(self):
        offset = 0
        remaining_relays = 1
        while remaining_relays > 0:
            summary_data = self._get_relay_summary(offset)  # request 1
            if not summary_data or "relays" not in summary_data:
                break

            fingerprints = ",".join(
                [relay.get("f") for relay in summary_data.get("relays", [])]
            )
            details_data = self._get_relay_details(fingerprints)  # request 2
            if not details_data or "relays" not in details_data:
                break

            offset += len(details_data.get("relays", []))
            remaining_relays = summary_data.get("relays_truncated", 0)
            for relay in details_data.get("relays", []):
                self.analyze(relay)

    def _get_relay_summary(self, offset: int) -> dict:
        url = f"https://onionoo.torproject.org/summary?limit=150&offset={offset}&running=true"
        response = self._make_request(url, sort=False)
        if response:
            data = response.json()
            return data
        return {}

    def _get_relay_details(self, fingerprints: str) -> dict:
        url = f"https://onionoo.torproject.org/details?lookup={fingerprints}"
        response = self._make_request(url, sort=False)
        if response:
            return response.json()
        return {}

    def analyze(self, relay):
        if "Exit" not in relay.get("flags", []):
            return

        context = {
            "name": relay.get("nickname"),
            "fingerprint": relay.get("fingerprint"),
            "last_seen": relay.get("last_seen"),
            "country": relay.get("country"),
            "country_name": relay.get("country_name"),
            "as": relay.get("as"),
            "as_name": relay.get("as_name"),
            "contact": relay.get("contact"),
            "source": self.name,
            "description": f"Tor exit node: {relay.get('nickname')} ",
            "hostname": relay.get("verified_host_names", []),
        }

        for address in relay.get("exit_addresses", []):
            ip_obs = ipv4.IPv4(value=address).save()
            ip_obs.add_context(self.name, context)
            ip_obs.tag(["tor", "exit_node"])

            for verified_hostname in relay.get("verified_host_names", []):
                host = hostname.Hostname(value=verified_hostname).save()
                host.tag(["tor", "exit_node"])
                host.link_to(
                    ip_obs, "resolves to", "Resolution provided by Tor exit node feed."
                )


taskmanager.TaskManager.register_task(TorExitNodes)
