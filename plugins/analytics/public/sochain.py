"""On-demand SoChain lookup of Bitcoin, Litecoin, Dogecoin and Zcash wallets."""

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import requests

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import task
from core.schemas.observable import Observable, ObservableType
from core.schemas.observables import wallet

API_URL = "https://sochain.com/api/v3"
ROWS = 25
NETWORKS = ("BTC", "LTC", "DOGE", "ZEC")
COINS = {
    "btc": "BTC",
    "bitcoin": "BTC",
    "ltc": "LTC",
    "litecoin": "LTC",
    "doge": "DOGE",
    "dogecoin": "DOGE",
    "zec": "ZEC",
    "zcash": "ZEC",
}
# Tried first when the address starts like this; every network is still tried in the end.
PREFIXES = {
    "BTC": ("bc1", "1", "3"),
    "LTC": ("ltc1", "L", "M", "3"),
    "DOGE": ("D", "A", "9"),
    "ZEC": ("t1", "t3"),
}


def get(endpoint: str, network: str, address: str, **params) -> dict | None:
    """The data of a SoChain answer, or None when SoChain answers 404."""
    headers = {"Accept": "application/json"}
    api_key = yeti_config.get("sochain", "api_key")
    if api_key:
        headers["API-KEY"] = api_key
    try:
        response = requests.get(
            f"{API_URL}/{endpoint}/{network}/{address}",
            params=params,
            headers=headers,
            proxies=yeti_config.get("proxy"),
            timeout=15,
            allow_redirects=False,
        )
    except requests.RequestException:
        # Request exceptions may contain request details; do not log the key.
        raise RuntimeError("SoChain request failed or timed out.") from None
    if response.status_code == 404:
        return None
    if response.status_code == 401:
        raise RuntimeError(
            "SoChain refused the API key; check api_key under [sochain]."
        )
    if response.status_code == 429:
        raise RuntimeError(
            "SoChain's lookup limit is reached; an API key from "
            "https://sochain.com/dashboard raises it."
        )
    if response.status_code != 200:
        raise RuntimeError(f"SoChain returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError("SoChain returned invalid JSON.") from None
    if (
        not isinstance(payload, dict)
        or payload.get("status") != "success"
        or not isinstance(payload.get("data"), dict)
    ):
        raise RuntimeError("SoChain returned an invalid answer.")
    return payload["data"]


def _field(data: dict, key: str):
    """data[key], or a clear error when SoChain's answer lacks it."""
    try:
        return data[key]
    except (KeyError, TypeError):
        raise RuntimeError(f"SoChain's answer has no {key!r} field.") from None


def is_address(value) -> bool:
    """Whether a value has the shape of a BTC, LTC, DOGE or ZEC address."""
    return isinstance(value, str) and value.isalnum() and value.isascii()


def parse_wallet(observable: Observable) -> tuple[str | None, str]:
    """The network named by the wallet's coin (None if it names none) and its address."""
    coin = getattr(observable, "coin", None)
    address = getattr(observable, "address", None)
    if not address:
        # "<coin>:<address>", "<coin>/<address>" or just the address
        value = observable.value.strip()
        for separator in (":", "/"):
            if separator in value:
                coin, address = value.split(separator, 1)
                break
        else:
            address = value
    address = address.strip()
    if not is_address(address):
        raise ValueError(f"{address!r} is not a cryptocurrency address.")
    if coin and coin.strip():
        network = COINS.get(coin.strip().lower())
        if network is None:
            raise ValueError(
                f"SoChain looks up BTC, LTC, DOGE and ZEC wallets, not {coin}."
            )
        return network, address
    return None, address


def detect_network(address: str) -> str | None:
    hinted = [n for n in NETWORKS if address.startswith(PREFIXES[n])]
    for network in hinted + [n for n in NETWORKS if n not in hinted]:
        data = get("is_valid_address", network, address)
        if data and data.get("is_valid"):
            return network
    return None


def _coin(amount) -> Decimal:
    try:
        return Decimal(amount)
    except (InvalidOperation, TypeError):
        raise RuntimeError("SoChain returned an invalid amount.") from None


def _block(block: dict | None) -> dict | None:
    if not block:
        return None
    try:
        time = datetime.fromtimestamp(int(_field(block, "time")), tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        raise RuntimeError("SoChain returned an invalid block time.") from None
    return {"height": block.get("height"), "time": time.isoformat()}


def lookup(network: str | None, address: str) -> dict:
    """SoChain's summary, counterparties and address poisoning findings for an address."""
    if network is None:
        network = detect_network(address)
        if network is None:
            raise ValueError(f"{address} is not a BTC, LTC, DOGE or ZEC address.")
    summary = get("address_summary", network, address)
    if summary is None:
        raise ValueError(f"{address} is not a valid {network} address.")
    counterparties = get("address_counterparties", network, address, limit=ROWS) or {}
    # None: SoChain has no poisoning check for this network.
    poisoning = get("address_poisoning", network, address, limit=ROWS)

    balance = _coin(_field(summary, "confirmed_balance"))
    received = _coin(_field(summary, "confirmed_received"))
    findings = (poisoning or {}).get("findings") or []
    return {
        "network": network,
        "address": address,
        "balance": format(balance, "f"),
        "unconfirmed_balance": format(
            _coin(summary.get("unconfirmed_balance") or "0"), "f"
        ),
        "total_received": format(received, "f"),
        # Confirmed received minus confirmed balance.
        "total_sent": format(received - balance, "f"),
        "txs_total": summary.get("txs_total"),
        "txs_received": summary.get("txs_received"),
        "txs_sent": summary.get("txs_sent"),
        "first_active": _block(summary.get("first_active")),
        "last_active": _block(summary.get("last_active")),
        "address_poisoning": {
            "checked": poisoning is not None,
            "targeted": bool(findings),
            "building": bool((poisoning or {}).get("building")),
            "findings": findings,
        },
        "counterparties": counterparties.get("counterparties") or [],
        "url": f"https://sochain.com/{network.lower()}/address/{address}",
    }


class SoChainWallet(task.OneShotTask):
    _defaults = {
        "group": "SoChain",
        "name": "SoChain Wallet",
        "description": "Look up a BTC, LTC, DOGE or ZEC wallet's balance, activity, "
        "counterparties and address poisoning on SoChain.",
    }
    acts_on: list[ObservableType] = [ObservableType.wallet]

    def each(self, observable: Observable):
        network, address = parse_wallet(observable)
        report = lookup(network, address)
        observable.add_context("SoChain", report, overwrite=True)
        coin = report["network"].lower()
        seen = set()
        for finding in report["address_poisoning"]["findings"]:
            sender = finding.get("sender")
            if not sender or sender == address or sender in seen:
                continue
            if not is_address(sender):
                self.logger.warning(
                    f"Skipping SoChain finding with invalid sender {sender!r}"
                )
                continue
            seen.add(sender)
            lookalike = wallet.Wallet(
                value=f"{coin}/{sender}", coin=coin, address=sender
            ).save()
            lookalike.link_to(
                observable,
                "address-poisoning",
                f"SoChain: sent dust imitating {finding.get('imitates')}",
            )


taskmanager.TaskManager.register_task(SoChainWallet)
