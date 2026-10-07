"""On-demand IsMalicious reputation enrichment, without automatic verdict tags."""

from urllib.parse import urlencode

import requests

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observable import Observable, ObservableType

API_URL = "https://api.ismalicious.com/check"


def fetch_report(indicator: str) -> dict:
    credential = yeti_config.get("ismalicious", "api_credential")
    if not credential:
        raise RuntimeError(
            "Configure IsMalicious api_credential (Base64 of apiKey:apiSecret)."
        )
    if not indicator.strip():
        raise ValueError("An indicator is required.")
    try:
        response = requests.get(
            API_URL,
            params={"query": indicator, "enrichment": "standard"},
            headers={"X-API-KEY": credential, "Accept": "application/json"},
            proxies=yeti_config.get("proxy"),
            timeout=30,
            allow_redirects=False,
        )
    except requests.RequestException:
        # Request exceptions may contain request details; do not log credentials.
        raise RuntimeError("IsMalicious request failed or timed out.") from None
    if response.status_code != 200:
        if response.status_code in (401, 403):
            message = "IsMalicious authentication failed; check api_credential."
        elif response.status_code == 429:
            message = "IsMalicious quota or rate limit reached; retry later."
        else:
            message = f"IsMalicious returned HTTP {response.status_code}."
        raise RuntimeError(message)
    try:
        report = response.json()
    except ValueError:
        raise RuntimeError("IsMalicious returned invalid JSON.") from None
    if not isinstance(report, dict) or "error" in report:
        raise RuntimeError("IsMalicious returned an invalid report.")
    return report


class IsMaliciousReport(task.OneShotTask):
    _defaults = {
        "group": "IsMalicious",
        "name": "IsMalicious Report",
        "description": "Look up indicator reputation and evidence with IsMalicious.",
    }
    acts_on: list[ObservableType] = [
        ObservableType.ipv4,
        ObservableType.ipv6,
        ObservableType.hostname,
        ObservableType.url,
        ObservableType.md5,
        ObservableType.sha1,
        ObservableType.sha256,
    ]

    def each(self, observable: Observable):
        report = fetch_report(observable.value)
        observable.add_context(
            "IsMalicious",
            {
                "source": "IsMalicious",
                "report_url": "https://ismalicious.com/report?"
                + urlencode({"query": observable.value}),
                # Keep unknown hashes, delisting, contradictions, and provenance intact.
                "report": report,
            },
            overwrite=True,
        )


taskmanager.TaskManager.register_task(IsMaliciousReport)
