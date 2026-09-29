import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import httpx

from core import database_arango
from core.schemas import observable
from core.schemas.entities.investigation import Investigation
from plugins.analytics.public import ioc_extractor


def sse(event: dict) -> str:
    """Frames an event the way the agent service does: 'data: {json}\\n\\n'."""
    return f"data: {json.dumps(event)}\n\n"


def agent_report(title: str) -> dict:
    """A final agent answer, wrapped in the ADK event envelope."""
    report = {
        "title": title,
        "summary": "Report summary",
        "iocs": [{"value": "1.2.3.4", "type": "ipv4", "description": "C2 server"}],
    }
    return {"content": {"parts": [{"text": json.dumps(report)}]}}


def investigations() -> list[Investigation]:
    """Lists Investigations only. count() would count every entity type."""
    return list(Investigation.list())


class IOCExtractorSelectionTest(unittest.TestCase):
    """Which URLs a run hands to the agent, and which it leaves alone."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        defaults = ioc_extractor.IOCExtractor._defaults.copy()
        self.analytics = ioc_extractor.IOCExtractor(**defaults)

    def tagged_url(self, value: str, tags=(ioc_extractor.FILTER_TAG,)):
        url = observable.save(value=value)
        url.tag(list(tags))
        return url

    def analyzed_by_run(self) -> list[str]:
        """Runs the task and returns the URLs it handed to the agent."""
        with mock.patch.object(
            ioc_extractor.IOCExtractor, "process_url"
        ) as process_url:
            self.analytics.run()
        return [call.args[2].value for call in process_url.call_args_list]

    def run_against(self, handler) -> None:
        """Runs the task with the agent service replaced by `handler`."""
        # Built before patching: the patch replaces httpx.Client for every
        # caller, this one included.
        client = httpx.Client(transport=httpx.MockTransport(handler))
        with mock.patch(
            "plugins.analytics.public.ioc_extractor.httpx.Client",
            return_value=client,
        ):
            self.analytics.run()

    def test_fresh_url_is_analyzed(self) -> None:
        """A freshly tagged URL is sent to the agent, once."""
        url = self.tagged_url("http://fresh.example.com/report")

        self.assertEqual(self.analyzed_by_run(), [url.value])

    def test_expired_url_is_not_analyzed_again(self) -> None:
        """expire_tag() is how a run marks a URL done; the next run skips it."""
        url = self.tagged_url("http://done.example.com/report")
        url.expire_tag(ioc_extractor.FILTER_TAG)

        self.assertEqual(self.analyzed_by_run(), [])

    def test_retagged_url_is_analyzed_again(self) -> None:
        """Tagging a processed URL again is how an analyst asks for a re-run."""
        url = self.tagged_url("http://retag.example.com/report")
        url.expire_tag(ioc_extractor.FILTER_TAG)
        url = observable.Observable.get(url.id)
        assert url is not None
        url.tag([ioc_extractor.FILTER_TAG])

        self.assertEqual(self.analyzed_by_run(), [url.value])

    def test_tag_past_its_expiry_but_not_yet_swept_is_analyzed(self) -> None:
        """The guard reads the tag's `fresh` flag, not its `expires` date.

        Exports go by `fresh` too, and ExpireTags clears it only on its next
        sweep after `expires` (every 12 h by default). A tag in this state
        belongs to a URL whose analysis has not completed since it was tagged,
        so analyzing it once more is harmless.
        """
        url = observable.save(value="http://lag.example.com/report")
        url.tag([ioc_extractor.FILTER_TAG], expiration=timedelta(hours=-1))
        filter_tag = url.get_tags()[ioc_extractor.FILTER_TAG]
        self.assertTrue(filter_tag.fresh)
        self.assertLess(filter_tag.expires, datetime.now(timezone.utc))

        self.assertEqual(self.analyzed_by_run(), [url.value])

    def test_another_fresh_tag_does_not_revive_an_expired_filter_tag(self) -> None:
        """Freshness is checked on the filter tag itself, not on any tag.

        A query that asks for tags.name == FILTER_TAG and tags.fresh == true
        as two conditions matches this URL, because each condition can be
        satisfied by a different tag.
        """
        url = self.tagged_url(
            "http://mixed.example.com/report",
            tags=(ioc_extractor.FILTER_TAG, "phishing"),
        )
        url.expire_tag(ioc_extractor.FILTER_TAG)

        self.assertEqual(self.analyzed_by_run(), [])

    def test_tag_that_only_resembles_the_filter_tag_is_not_analyzed(self) -> None:
        """Only a tag named exactly FILTER_TAG queues a URL.

        filter() matches strings as a LIKE pattern, '%extract_iocs%', in which
        '_' matches any one character. Both tags below match it, and
        expire_tag(FILTER_TAG) could never mark such a URL done.
        """
        self.tagged_url("http://other.example.com/report", tags=("no_extract_iocs",))
        self.tagged_url("http://typo.example.com/report", tags=("extract-iocs",))

        self.assertEqual(self.analyzed_by_run(), [])

    def test_second_run_does_not_create_another_investigation(self) -> None:
        """A URL analyzed by one run is not sent to the agent by the next.

        The mocked agent titles each report differently, as an LLM may, and
        Investigation is keyed by name, so a second analysis creates a second
        Investigation instead of updating the first.
        """
        self.tagged_url("http://report.example.com/apt")
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            report = agent_report(f"Report title {len(requests)}")
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=iter([sse(report).encode()]),
            )

        self.run_against(handler)
        self.assertEqual(len(investigations()), 1)
        self.run_against(handler)
        self.assertEqual(len(investigations()), 1)
        self.assertEqual(len(requests), 1)

    def test_failed_run_is_retried_on_the_next_run(self) -> None:
        """A failure leaves the tag fresh, so the next run tries again."""
        self.tagged_url("http://flaky.example.com/report")
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(500, text="Internal Server Error")

        self.run_against(handler)
        self.run_against(handler)

        self.assertEqual(len(requests), 2)
        self.assertEqual(len(investigations()), 0)


if __name__ == "__main__":
    unittest.main()
