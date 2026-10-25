"""On-demand DarkEye lookup of ransomware, breach, lead and stealer records.

DarkEye (https://darkeye.io) serves this data through two APIs: Have I Been
Ransomed? (leak metadata per domain) and Breach House (ransomware victims,
data breaches, leads and stealer logs). The task queries each one that has a
key configured.
"""

import re
import unicodedata

import requests

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observable import Observable, ObservableType

HIBR = "Have I Been Ransomed?"
HIBR_URL = "https://haveibeenransom.com/api/metadata/domain"
HIBR_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breaches"}
DEFAULT_MAX_PAGES = 5

BREACH_HOUSE = "Breach House"
BREACH_HOUSE_URL = "https://breach.house/api/v1/search"
BREACH_HOUSE_SOURCES = ("ransomware", "breaches", "leads", "stealers")
DEFAULT_LIMIT = 25
MAX_LIMIT = 200

# The APIs treat * and ? as wildcards, so only plain domain names are queried.
DOMAIN_REGEX = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def clean(value) -> str:
    # Some group and source names use styled Unicode characters and irregular spacing.
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).split())


def get_json(product: str, url: str, api_key: str, params=None) -> dict:
    try:
        response = requests.get(
            url,
            params=params,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            proxies=yeti_config.get("proxy"),
            timeout=30,
            allow_redirects=False,
        )
    except requests.RequestException:
        # Request exceptions may contain request details; do not log the key.
        raise RuntimeError(f"{product} request failed or timed out.") from None
    if response.status_code != 200:
        if response.status_code in (401, 403):
            message = f"{product} authentication failed; check its API key."
        elif response.status_code == 429:
            message = f"{product} quota or rate limit reached; retry later."
        else:
            message = f"{product} returned HTTP {response.status_code}."
        raise RuntimeError(message)
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError(f"{product} returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise RuntimeError(f"{product} returned an invalid response.")
    return data


def record(product: str, category: str, item: dict) -> dict:
    # Only listing metadata is kept: no leaked records, proof files, leak-site
    # or download URLs.
    return {
        "product": product,
        "category": category,
        "id": clean(item.get("victim_id") or item.get("id_source") or item.get("id")),
        "title": clean(item.get("post_title"))
        or clean(item.get("name"))
        or clean(item.get("website")),
        "website": clean(item.get("website")),
        "group": clean(item.get("group_name")),
        "country": clean(item.get("country")),
        "discovered": clean(item.get("discovered"))[:10],
    }


def fetch_hibr(domain: str, api_key: str) -> tuple[list[dict], bool]:
    """Returns HIBR leaks for a domain, and whether max_pages cut the list short."""
    max_pages = yeti_config.get("darkeye", "max_pages") or DEFAULT_MAX_PAGES
    max_pages = max(1, int(max_pages))
    records = []
    seen = set()
    for page in range(1, max_pages + 1):
        url = f"{HIBR_URL}/{domain}" if page == 1 else f"{HIBR_URL}/{domain}/{page}"
        data = get_json(HIBR, url, api_key)
        # The API returns "sources" and a top-level "has_next"; its docs show
        # "results" and "pagination".
        pagination = data.get("pagination")
        if not isinstance(pagination, dict):
            pagination = {}
        for leak in data.get("sources") or data.get("results") or []:
            if not isinstance(leak, dict):
                continue
            # A leak indexed while paging is repeated on a later page.
            leak_id = clean(leak.get("id_source") or leak.get("id"))
            if not leak_id or leak_id in seen:
                continue
            seen.add(leak_id)
            leak_type = clean(leak.get("leak_type"))
            category = HIBR_CATEGORIES.get(leak_type, leak_type)
            records.append(record(HIBR, category, leak))
        # A page can be short or empty and still have a next page.
        if not data.get("has_next", pagination.get("has_next", False)):
            return records, False
    return records, True


def fetch_breach_house(domain: str, api_key: str) -> tuple[list[dict], bool]:
    """Returns Breach House records for a domain, and whether limit cut a source short."""
    limit = yeti_config.get("darkeye", "limit") or DEFAULT_LIMIT
    limit = min(max(1, int(limit)), MAX_LIMIT)
    data = get_json(
        BREACH_HOUSE, BREACH_HOUSE_URL, api_key, params={"q": domain, "limit": limit}
    )
    records = []
    truncated = False
    for source in BREACH_HOUSE_SOURCES:
        items = data.get(source) or []
        if isinstance(items, dict):
            items = items.get("results") or []
        if not isinstance(items, list):
            continue
        if len(items) >= limit:
            truncated = True
        for item in items:
            if isinstance(item, dict):
                records.append(record(BREACH_HOUSE, source, item))
    return records, truncated


def fetch_records(domain: str) -> tuple[list[dict], list[str], bool]:
    """Returns the records tied to a domain, the products queried and truncation."""
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_REGEX.match(domain):
        raise ValueError("A plain domain name is required.")
    fetchers = []
    hibr_key = yeti_config.get("darkeye", "haveibeenransom_api_key")
    if hibr_key:
        fetchers.append((HIBR, fetch_hibr, hibr_key))
    breach_house_key = yeti_config.get("darkeye", "breachhouse_api_key")
    if breach_house_key:
        fetchers.append((BREACH_HOUSE, fetch_breach_house, breach_house_key))
    if not fetchers:
        raise RuntimeError(
            "Configure haveibeenransom_api_key or breachhouse_api_key under [darkeye]."
        )

    records = []
    products = []
    truncated = False
    for product, fetch, api_key in fetchers:
        product_records, product_truncated = fetch(domain, api_key)
        records.extend(product_records)
        products.append(product)
        truncated = truncated or product_truncated
    return records, products, truncated


class DarkEyeLookup(task.OneShotTask):
    _defaults = {
        "group": "DarkEye",
        "name": "DarkEye Lookup",
        "description": (
            "List ransomware victims, data breaches, leads and stealer logs tied "
            "to a domain (Have I Been Ransomed? and Breach House)."
        ),
    }
    acts_on: list[ObservableType] = [ObservableType.hostname]

    def each(self, observable: Observable):
        records, products, truncated = fetch_records(observable.value)
        observable.add_context(
            "DarkEye",
            {
                "products": products,
                "record_count": len(records),
                "truncated": truncated,
                "records": records,
            },
            overwrite=True,
        )


taskmanager.TaskManager.register_task(DarkEyeLookup)
