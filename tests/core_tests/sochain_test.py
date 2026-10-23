"""SoChain wallet lookups with mocked HTTP; no network calls."""

import importlib
import unittest
from unittest.mock import Mock, patch

import requests

from core import taskmanager
from core.schemas.observables import wallet

with patch.object(taskmanager.TaskManager, "register_task"):
    sochain = importlib.import_module("plugins.analytics.public.sochain")

BTC = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj"
PAID = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPPz"
LOOKALIKE = "36bLmGg2pQ71rSZyxaUGmk8ggu6Lp5VPZz"
DOGE = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"

# Shaped as SoChain answered on 23 Oct 2026, cut to a few rows.
SUMMARY = {
    "txs_sent": 1796,
    "txs_received": 32014,
    "txs_total": 32014,
    "confirmed_balance": "0.12771030",
    "unconfirmed_balance": "0.00000000",
    "confirmed_received": "285785.38685032",
    "first_active": {"height": 687848, "time": 1623874601},
    "last_active": {"height": 972455, "time": 1792576976},
}
COUNTERPARTIES = {
    "address": BTC,
    "window_blocks": 4320,
    "from_height": 968436,
    "building": False,
    "counterparties": [
        {
            "address": PAID,
            "direction": "sent",
            "amount": "0.01017653",
            "txid": "95" * 32,
            "height": 972455,
        }
    ],
}
POISONING = {
    "address": BTC,
    "building": False,
    "findings": [
        {
            "dust_txid": "dd" * 32,
            "amount": "0.00000546",
            "sender": LOOKALIKE,
            "imitates": PAID,
            "real_txid": "95" * 32,
            "real_height": 972455,
            "real_amount": "0.01017653",
            "receiver_paid": False,
            "shared_prefix": 4,
            "shared_suffix": 4,
            "sender_kind": "new",
            "sender_txs": 1,
            "height": 972460,
            "confirmed": True,
        }
    ],
}


def answer(data=None, status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = (
        payload if payload is not None else {"status": "success", "data": data}
    )
    return response


class SoChainTest(unittest.TestCase):
    def setUp(self):
        self.api_key = None
        config = patch.object(sochain.yeti_config, "get")
        self.get_config = config.start()
        self.get_config.side_effect = lambda section, key=None: (
            self.api_key if section == "sochain" else {}
        )
        self.addCleanup(config.stop)
        self.valid_on = ("BTC",)
        self.answers = {
            "address_summary": answer(SUMMARY),
            "address_counterparties": answer(COUNTERPARTIES),
            "address_poisoning": answer(POISONING),
        }
        http = patch.object(sochain.requests, "get", side_effect=self.http)
        self.get = http.start()
        self.addCleanup(http.stop)

    def http(self, url, **kwargs):
        endpoint, network = url.split("/api/v3/")[1].split("/")[:2]
        if endpoint == "is_valid_address":
            return answer({"is_valid": network in self.valid_on})
        return self.answers[endpoint]

    def urls(self):
        return [call.args[0] for call in self.get.call_args_list]

    def test_report(self):
        report = sochain.lookup("BTC", BTC)
        self.assertEqual(report["network"], "BTC")
        self.assertEqual(report["balance"], "0.12771030")
        self.assertEqual(report["total_received"], "285785.38685032")
        # received minus balance, exactly
        self.assertEqual(report["total_sent"], "285785.25914002")
        self.assertEqual(report["unconfirmed_balance"], "0.00000000")
        self.assertEqual(report["txs_total"], 32014)
        self.assertEqual(
            report["first_active"],
            {"height": 687848, "time": "2021-06-16T20:16:41+00:00"},
        )
        self.assertTrue(report["address_poisoning"]["targeted"])
        self.assertEqual(report["counterparties"][0]["address"], PAID)
        self.assertEqual(report["url"], f"https://sochain.com/btc/address/{BTC}")
        self.assertFalse(any("is_valid_address" in url for url in self.urls()))
        self.assertEqual(self.get.call_args.kwargs["timeout"], 15)
        self.assertFalse(self.get.call_args.kwargs["allow_redirects"])

    def test_parse_wallet(self):
        cases = [
            (wallet.Wallet(value=f"btc/{BTC}", coin="btc", address=BTC), ("BTC", BTC)),
            (wallet.Wallet(value=f"DOGE:{DOGE}"), ("DOGE", DOGE)),
            (wallet.Wallet(value=f"Litecoin/{DOGE}"), ("LTC", DOGE)),
            # a MISP btc attribute is imported as a wallet holding the address
            (wallet.Wallet(value=DOGE), (None, DOGE)),
        ]
        for observable, expected in cases:
            with self.subTest(value=observable.value):
                self.assertEqual(sochain.parse_wallet(observable), expected)
        for value in (f"xmr/{BTC}", "btc/not an address", "eth:0x12;"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    sochain.parse_wallet(wallet.Wallet(value=value))

    def test_network_detection(self):
        self.valid_on = ("DOGE",)
        report = sochain.lookup(None, DOGE)
        self.assertEqual(report["network"], "DOGE")
        tried = [url.split("/")[-2] for url in self.urls() if "is_valid_address" in url]
        # a D address is tried on Dogecoin first
        self.assertEqual(tried, ["DOGE"])

        self.valid_on = ()
        with self.assertRaises(ValueError):
            sochain.lookup(None, DOGE)

    def test_network_without_poisoning_check(self):
        self.answers["address_poisoning"] = answer(status_code=404, payload={})
        report = sochain.lookup("BTC", BTC)
        self.assertFalse(report["address_poisoning"]["checked"])

    def test_unknown_address(self):
        self.answers["address_summary"] = answer(status_code=404, payload={})
        with self.assertRaises(ValueError):
            sochain.lookup("BTC", BTC)

    def test_api_key_header(self):
        sochain.lookup("BTC", BTC)
        self.assertNotIn("API-KEY", self.get.call_args.kwargs["headers"])
        self.api_key = "synthetic-key"
        sochain.lookup("BTC", BTC)
        self.assertEqual(
            self.get.call_args.kwargs["headers"]["API-KEY"], "synthetic-key"
        )
        self.assertNotIn("synthetic-key", self.get.call_args.args[0])

    def test_http_errors(self):
        for status in (302, 401, 429, 500):
            with self.subTest(status=status):
                self.answers["address_summary"] = answer(status_code=status, payload={})
                with self.assertRaises(RuntimeError):
                    sochain.lookup("BTC", BTC)
        self.get.side_effect = requests.Timeout("sensitive request details")
        with self.assertRaisesRegex(RuntimeError, "failed or timed out") as caught:
            sochain.lookup("BTC", BTC)
        self.assertNotIn("sensitive", str(caught.exception))

    @patch.object(sochain.wallet.Wallet, "link_to")
    @patch.object(sochain.Observable, "save", autospec=True)
    def test_each_adds_context_and_links_lookalikes(self, save, link_to):
        save.side_effect = lambda self, *args, **kwargs: self
        observable = wallet.Wallet(value=f"btc/{BTC}", coin="btc", address=BTC)
        action = sochain.SoChainWallet(**sochain.SoChainWallet._defaults)
        action.each(observable)
        contexts = [c for c in observable.context if c["source"] == "SoChain"]
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["balance"], "0.12771030")
        saved = save.call_args.args[0]
        self.assertEqual(
            (saved.value, saved.coin, saved.address),
            (f"btc/{LOOKALIKE}", "btc", LOOKALIKE),
        )
        self.assertEqual(link_to.call_args.args[:2], (observable, "address-poisoning"))
        self.assertIn(PAID, link_to.call_args.args[2])

        # a second lookup replaces the context
        action.each(observable)
        self.assertEqual(
            len([c for c in observable.context if c["source"] == "SoChain"]), 1
        )
