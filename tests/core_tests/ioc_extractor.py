import json
import logging
import unittest
from unittest import mock

from core import database_arango
from core.schemas import observable
from core.schemas.entities.investigation import Investigation
from core.schemas.observable import Observable, ObservableType
from plugins.analytics.public import ioc_extractor


def sse(event: dict) -> str:
    """Frames an event the way the agent service does: 'data: {json}\\n\\n'."""
    return f"data: {json.dumps(event)}\n\n"


def agent_text(payload) -> dict:
    """Wraps a final agent answer in the ADK event envelope."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"content": {"parts": [{"text": text}]}}


VALID_REPORT = {
    "title": "Report title",
    "summary": "Report summary",
    "tags": ["apt", "phishing"],
    "last_updated": "2026-08-01",
    "external_references": [],
    "iocs": [
        {"value": "1.2.3.4", "type": "ipv4", "description": "C2 server"},
        {"value": "evil.example.com", "type": "domain", "description": "Phishing"},
    ],
}


class FakeStream:
    """Stands in for the context manager returned by httpx.Client.stream."""

    def __init__(self, chunks: list[str]):
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_text(self):
        yield from self._chunks

    def iter_lines(self):
        buffered = "".join(self._chunks)
        yield from buffered.splitlines()


def fake_client(chunks: list[str]) -> mock.MagicMock:
    client = mock.MagicMock()
    client.stream.return_value = FakeStream(chunks)
    return client


class IOCExtractorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        defaults = ioc_extractor.IOCExtractor._defaults.copy()
        self.analytics = ioc_extractor.IOCExtractor(**defaults)
        self.url = observable.save(value="http://report.example.com/apt")
        self.url.tag([ioc_extractor.FILTER_TAG])

    def run_with(self, chunks: list[str]) -> None:
        self.analytics.process_url(
            fake_client(chunks), "http://agent/endpoint", self.url
        )

    def test_malformed_response_writes_nothing(self) -> None:
        """A response that is not valid JSON must not create any objects."""
        self.run_with([sse(agent_text("this is not json at all"))])

        self.assertEqual(Investigation.count(), 0)
        self.assertEqual(len(Observable.filter({"value": "1.2.3.4"})[0]), 0)

    def test_response_missing_required_fields_writes_nothing(self) -> None:
        """Well-formed JSON of the wrong shape must not create any objects."""
        self.run_with([sse(agent_text({"unexpected": "shape"}))])

        self.assertEqual(Investigation.count(), 0)

    def test_valid_report_is_saved_with_iocs(self) -> None:
        """The happy path creates the investigation and links its IOCs."""
        self.run_with([sse(agent_text(VALID_REPORT))])

        self.assertEqual(Investigation.count(), 1)
        investigation = Investigation.find(name="Report title")
        assert investigation is not None
        self.assertEqual(investigation.description, "Report summary")

    def test_agent_domain_type_is_translated_to_hostname(self) -> None:
        """The agent's vocabulary is mapped onto Yeti's.

        The agent says 'domain'; Yeti has no such type and calls it a hostname.
        """
        ioc = ioc_extractor.IOC(
            value="evil.example.com", type="domain", description="Phishing"
        )

        built = self.analytics._build_observable(ioc)

        assert built is not None
        self.assertEqual(built.type, ObservableType.hostname)

    def test_ioc_of_unknown_agent_type_falls_back_to_guessing(self) -> None:
        """'other' carries no type information, so Yeti decides."""
        ioc = ioc_extractor.IOC(value="1.2.3.4", type="other", description="C2")

        built = self.analytics._build_observable(ioc)

        assert built is not None
        self.assertEqual(built.type, ObservableType.ipv4)

    def test_untypeable_ioc_does_not_drop_the_iocs_after_it(self) -> None:
        """A bad IOC is skipped; the ones that follow it are still stored."""
        report = json.loads(json.dumps(VALID_REPORT))
        report["iocs"].insert(
            0,
            {
                "value": "see report for hashes",
                "type": "other",
                "description": "not an observable",
            },
        )

        with self.assertLogs(level=logging.WARNING):
            self.run_with([sse(agent_text(report))])

        self.assertEqual(Investigation.count(), 1)
        self.assertEqual(
            len(Observable.filter({"value": "see report for hashes"})[0]), 0
        )
        # Both IOCs listed after the bad one must survive.
        self.assertEqual(len(Observable.filter({"value": "1.2.3.4"})[0]), 1)
        self.assertEqual(len(Observable.filter({"value": "evil.example.com"})[0]), 1)

    def test_mismatched_ioc_type_is_skipped(self) -> None:
        """A value contradicting its declared type is rejected, not re-guessed.

        Yeti would happily guess 'evil.example.com' as a hostname; the agent
        calling it an ipv4 means one of the two is wrong, so it is not stored.
        """
        report = json.loads(json.dumps(VALID_REPORT))
        report["iocs"] = [
            {"value": "evil.example.com", "type": "ipv4", "description": "bad"}
        ]

        with self.assertLogs(level=logging.WARNING):
            self.run_with([sse(agent_text(report))])

        self.assertEqual(len(Observable.filter({"value": "evil.example.com"})[0]), 0)

    def test_two_events_in_one_chunk(self) -> None:
        """The stream may deliver several SSE frames in a single chunk."""
        self.run_with(
            [sse(agent_text({"content": "ignored"})) + sse(agent_text(VALID_REPORT))]
        )

        self.assertEqual(Investigation.count(), 1)

    def test_keepalive_lines_are_ignored(self) -> None:
        """SSE comments and blank lines must not abort processing."""
        self.run_with([": keep-alive\n\n", sse(agent_text(VALID_REPORT))])

        self.assertEqual(Investigation.count(), 1)

    def test_agent_error_event_is_logged_and_writes_nothing(self) -> None:
        """An error event from the agent is reported, not silently retried."""
        error = {"error": "quota exceeded", "error_type": "RESOURCE_EXHAUSTED"}

        with self.assertLogs(level=logging.ERROR) as logs:
            self.run_with([sse(error)])

        self.assertEqual(Investigation.count(), 0)
        self.assertTrue(
            any("RESOURCE_EXHAUSTED" in line for line in logs.output),
            f"error_type not surfaced in logs: {logs.output}",
        )

    def test_successful_run_expires_the_filter_tag(self) -> None:
        """A processed URL is not picked up again on the next run."""
        self.run_with([sse(agent_text(VALID_REPORT))])

        refreshed = Observable.find(value=self.url.value)
        assert refreshed is not None
        tags = refreshed.get_tags()
        self.assertIn(ioc_extractor.FILTER_TAG, tags)
        self.assertFalse(tags[ioc_extractor.FILTER_TAG].fresh)

    def test_failed_run_keeps_the_filter_tag(self) -> None:
        """A rejected response leaves the tag in place for a later retry."""
        self.run_with([sse(agent_text("not json"))])

        refreshed = Observable.find(value=self.url.value)
        assert refreshed is not None
        tags = refreshed.get_tags()
        self.assertIn(ioc_extractor.FILTER_TAG, tags)
        self.assertTrue(tags[ioc_extractor.FILTER_TAG].fresh)


if __name__ == "__main__":
    unittest.main()
