import json
import logging
import unittest

import httpx

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


def mock_client(chunks: list[str], status_code: int = 200) -> httpx.Client:
    """A real httpx.Client whose transport streams back `chunks` one at a time.

    What is under test is how the plugin reads lines out of the stream, so the
    lines have to come out of httpx's own LineDecoder, as they do in
    production. A mocked response would have to re-implement iter_lines(),
    and one that joins every chunk first makes a frame split across chunks
    impossible to test.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"content-type": "text/event-stream"},
            # An iterator rather than bytes, so each chunk reaches the client
            # as a separate read, the way a streamed response does.
            content=iter([chunk.encode() for chunk in chunks]),
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


class IOCExtractorTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        defaults = ioc_extractor.IOCExtractor._defaults.copy()
        self.analytics = ioc_extractor.IOCExtractor(**defaults)
        self.url = observable.save(value="http://report.example.com/apt")
        self.url.tag([ioc_extractor.FILTER_TAG])

    def run_with(self, chunks: list[str]) -> None:
        with mock_client(chunks) as client:
            self.analytics.process_url(client, "http://agent/endpoint", self.url)

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

    def test_frame_split_across_chunks_is_reassembled(self) -> None:
        """A frame split across chunks is parsed once it is whole.

        Chunk boundaries are set by the transport, not by the agent, so one
        'data:' frame can arrive in pieces. Only the split frame is sent here,
        so the split is the only thing that can make this fail.
        """
        frame = sse(agent_text(VALID_REPORT))
        mid = len(frame) // 2

        self.run_with([frame[:mid], frame[mid:]])

        self.assertEqual(Investigation.count(), 1)

    def test_unparseable_frame_is_skipped(self) -> None:
        """A 'data:' frame that is not JSON costs that frame, not the URL.

        The report may still arrive in a later frame, so one garbled event is
        logged and skipped rather than aborting the whole stream.
        """
        with self.assertLogs(level=logging.WARNING):
            self.run_with(["data: {not json\n\n", sse(agent_text(VALID_REPORT))])

        self.assertEqual(Investigation.count(), 1)

    def test_agent_error_event_is_logged_and_writes_nothing(self) -> None:
        """An error event from the agent is reported, not silently retried."""
        error = {"error": "quota exceeded", "error_type": "provider_error"}

        with self.assertLogs(level=logging.ERROR) as logs:
            self.run_with([sse(error)])

        self.assertEqual(Investigation.count(), 0)
        self.assertTrue(
            any("provider_error" in line for line in logs.output),
            f"error_type not surfaced in logs: {logs.output}",
        )
        # Guard: an agent error is not a processed URL, so its tag stays fresh.
        refreshed = Observable.find(value=self.url.value)
        assert refreshed is not None
        self.assertTrue(refreshed.get_tags()[ioc_extractor.FILTER_TAG].fresh)

    def test_successful_run_expires_the_filter_tag(self) -> None:
        """A processed URL is marked as done by expiring its filter tag."""
        self.run_with([sse(agent_text(VALID_REPORT))])

        refreshed = Observable.find(value=self.url.value)
        assert refreshed is not None
        tags = refreshed.get_tags()
        self.assertIn(ioc_extractor.FILTER_TAG, tags)
        self.assertFalse(tags[ioc_extractor.FILTER_TAG].fresh)

    def test_report_with_a_skipped_ioc_still_expires_the_filter_tag(self) -> None:
        """Skipping an unusable IOC does not turn the run into a failure.

        The rest of the report has been written, so the URL is marked as
        processed like any other rather than left queued for another attempt.
        """
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

    def test_http_error_writes_nothing_and_keeps_the_filter_tag(self) -> None:
        """An HTTP error from the agent service leaves the URL queued.

        A guard: the agent can fail before it starts streaming (a 500, for
        example), in which case the error arrives as an HTTP status rather
        than as an error event, and must not be mistaken for a processed URL.
        If the status were ignored, the 500's body (not a 'data:' frame) would
        fail the schema check and write nothing too, so the log check makes
        sure it is the HTTP status that stopped it.
        """
        with self.assertLogs(level=logging.ERROR) as logs:
            with mock_client(["Internal Server Error"], status_code=500) as client:
                self.analytics.process_url(client, "http://agent/endpoint", self.url)

        self.assertTrue(
            any("HTTP Error" in line for line in logs.output),
            f"HTTP status not reported as an HTTP error: {logs.output}",
        )
        self.assertEqual(Investigation.count(), 0)
        refreshed = Observable.find(value=self.url.value)
        assert refreshed is not None
        tags = refreshed.get_tags()
        self.assertIn(ioc_extractor.FILTER_TAG, tags)
        self.assertTrue(tags[ioc_extractor.FILTER_TAG].fresh)


if __name__ == "__main__":
    unittest.main()
