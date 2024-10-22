from unittest.mock import MagicMock, patch

from core import database_arango
from core.schemas.observable import ObservableType
from core.schemas.observables import ipv4
from plugins.feeds.public.tor_exit_nodes import TorExitNodes
from tests.helpers import YetiTestCase


class TorExitNodesTest(YetiTestCase):
    @classmethod
    def setUpClass(cls):
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    @patch("plugins.feeds.public.tor_exit_nodes.TorExitNodes._make_request")
    def test_tor_exit_node_parsing(self, mock_request):
        mock_response_summary = MagicMock()
        mock_response_summary.json.return_value = {
            "relays": [
                {
                    "n": "seele",
                    "f": "000A10D43011EA4928A35F610405F92B4433B4DC",
                    "a": ["104.53.221.159"],
                    "r": True,
                },
            ],
            "relays_truncated": 1,
        }

        mock_response_details = MagicMock()
        mock_response_details.json.return_value = {
            "relays": [
                {
                    "nickname": "seele",
                    "fingerprint": "000A10D43011EA4928A35F610405F92B4433B4DC",
                    "exit_addresses": ["104.53.221.159"],
                    "flags": ["Fast"],
                    "verified_host_names": ["seele.tor-exit.calyxinstitute.org"],
                },
            ]
        }

        mock_response_summary_2 = MagicMock()
        mock_response_summary_2.json.return_value = {
            "relays": [
                {
                    "n": "seele",
                    "f": "000A10D43011EA4928A35F610405F92B4433B4DC",
                    "a": ["104.53.221.159"],
                    "r": True,
                },
                {
                    "n": "tor4novgnet",
                    "f": "000C351F86033654A82D9FD6AC3B178F44E236BE",
                    "a": ["5.196.8.113"],
                    "r": True,
                },
            ],
            "relays_truncated": 0,
        }

        mock_response_details_2 = MagicMock()
        mock_response_details_2.json.return_value = {
            "relays": [
                {
                    "nickname": "seele",
                    "fingerprint": "000A10D43011EA4928A35F610405F92B4433B4DC",
                    "exit_addresses": ["104.53.221.159"],
                    "flags": ["Exit", "Fast"],
                    "verified_host_names": ["seele.tor-exit.calyxinstitute.org"],
                },
                {
                    "nickname": "tor4novgnet",
                    "fingerprint": "000C351F86033654A82D9FD6AC3B178F44E236BE",
                    "exit_addresses": ["5.196.8.113"],
                    "flags": ["Exit", "Fast", "Guard"],
                    "verified_host_names": ["tor4novgnet.tor-exit.calyxinstitute.org"],
                },
            ]
        }

        mock_request.side_effect = [
            mock_response_summary,
            mock_response_details,
            mock_response_summary_2,
            mock_response_details_2,
        ]

        defaults = TorExitNodes._defaults.copy()
        task = TorExitNodes(**defaults)

        task.run()

        expected_observable_values = [
            {
                "value": "104.53.221.159",
                "type": ObservableType.ipv4,
                "tags": {"tor", "exit_node"},
            },
            {
                "value": "5.196.8.113",
                "type": ObservableType.ipv4,
                "tags": {"tor", "exit_node"},
            },
            {
                "value": "seele.tor-exit.calyxinstitute.org",
                "type": ObservableType.hostname,
                "tags": {"tor", "exit_node"},
            },
            {
                "value": "tor4novgnet.tor-exit.calyxinstitute.org",
                "type": ObservableType.hostname,
                "tags": {"tor", "exit_node"},
            },
        ]

        self.check_observables(expected_observable_values)

        observable_1 = ipv4.IPv4.find(value="104.53.221.159")
        self.check_neighbors(observable_1, ["seele.tor-exit.calyxinstitute.org"])

        observable_2 = ipv4.IPv4.find(value="5.196.8.113")
        self.check_neighbors(observable_2, ["tor4novgnet.tor-exit.calyxinstitute.org"])
