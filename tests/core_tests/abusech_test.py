import os
import traceback
import unittest
from unittest import mock

from core.schemas import task
from plugins.feeds.public import abusech, abusech_malwarebazaar, threatfox, urlhaus

KEY = "0123456789abcdef0123456789abcdef0123456789abcdef"
FEEDS = (
    abusech_malwarebazaar.AbuseCHMalwareBazaaar,
    threatfox.ThreatFox,
    urlhaus.UrlHaus,
)


def with_key(key: str | None):
    env = {k: v for k, v in os.environ.items() if k != "YETI_ABUSECH_AUTH_KEY"}
    if key is not None:
        env["YETI_ABUSECH_AUTH_KEY"] = key
    return mock.patch.dict(os.environ, env, clear=True)


class AbuseCHExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.feed = threatfox.ThreatFox(**threatfox.ThreatFox._defaults.copy())

    def test_without_a_key_no_request_is_made(self) -> None:
        no_request = AssertionError("no request expected without a key")
        with (
            with_key(""),
            mock.patch.object(task.FeedTask, "_make_request", side_effect=no_request),
            self.assertRaisesRegex(RuntimeError, "YETI_ABUSECH_AUTH_KEY"),
        ):
            abusech.fetch_export(self.feed, "https://x/{auth_key}/recent.csv")

    def test_the_key_goes_in_the_url_path(self) -> None:
        response = mock.sentinel.response
        with (
            with_key(KEY),
            mock.patch.object(
                task.FeedTask, "_make_request", return_value=response
            ) as request,
        ):
            got = abusech.fetch_export(
                self.feed, "https://x/{auth_key}/recent.csv", sort=False
            )
        self.assertIs(got, response)
        request.assert_called_once_with(f"https://x/{KEY}/recent.csv", sort=False)

    def test_errors_do_not_reveal_the_key(self) -> None:
        def fail(url, **kwargs):
            raise RuntimeError(f"{url} returned code: 401")

        with (
            with_key(KEY),
            mock.patch.object(task.FeedTask, "_make_request", side_effect=fail),
            self.assertRaises(RuntimeError) as raised,
        ):
            abusech.fetch_export(self.feed, "https://x/{auth_key}/recent.csv")

        error = raised.exception
        self.assertEqual(
            str(error), f"https://x/{abusech.REDACTED}/recent.csv returned code: 401"
        )
        printed = "".join(traceback.format_exception(error))
        self.assertNotIn(KEY, printed)


class AbuseCHFeedsTest(unittest.TestCase):
    def test_feeds_use_the_authenticated_exports(self) -> None:
        for feed_class in FEEDS:
            with self.subTest(feed=feed_class.__name__):
                self.assertRegex(
                    feed_class._SOURCE,
                    r"^https://[a-z-]+\.abuse\.ch/v2/files/exports/\{auth_key\}/",
                )

    def test_feeds_without_a_key_fail_clearly(self) -> None:
        no_request = AssertionError("no request expected without a key")
        for feed_class in FEEDS:
            feed = feed_class(**feed_class._defaults.copy())
            with (
                self.subTest(feed=feed_class.__name__),
                with_key(None),
                mock.patch.object(
                    task.FeedTask, "_make_request", side_effect=no_request
                ),
                self.assertRaisesRegex(RuntimeError, "abuse.ch Auth-Key"),
            ):
                feed.run()
