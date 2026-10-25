import datetime
import unittest

from core import database_arango
from core.schemas import model, tag
from core.schemas.observables import ipv4

VALUE = "203.0.113.7"


class ConcurrentWritesTest(unittest.TestCase):
    """Two writers that loaded the same object keep each other's changes."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        ipv4.IPv4(value=VALUE).save()
        # Two feeds load the object before either one saves.
        self.first = ipv4.IPv4.find(value=VALUE)
        self.second = ipv4.IPv4.find(value=VALUE)

    def stored(self) -> ipv4.IPv4:
        stored = ipv4.IPv4.find(value=VALUE)
        assert stored is not None
        return stored

    def test_context_from_both_writers_is_kept(self) -> None:
        self.first.add_context("FeedA", {"seen": 1})
        self.second.add_context("FeedB", {"seen": 1})

        sources = [context["source"] for context in self.stored().context]
        self.assertCountEqual(sources, ["FeedA", "FeedB"])

    def test_tags_survive_a_stale_add_context(self) -> None:
        self.first.add_context("FeedA", {"seen": 1})
        self.first.tag(["feed-a"])
        self.second.add_context("FeedB", {"seen": 1})

        stored = self.stored()
        self.assertEqual([t.name for t in stored.tags], ["feed-a"])
        self.assertCountEqual(
            [context["source"] for context in stored.context], ["FeedA", "FeedB"]
        )

    def test_tags_from_both_writers_are_kept(self) -> None:
        self.first.tag(["feed-a"])
        self.second.tag(["feed-b"])

        self.assertCountEqual(
            [t.name for t in self.stored().tags], ["feed-a", "feed-b"]
        )

    def test_a_tag_both_writers_add_is_counted_once(self) -> None:
        self.first.tag(["shared"])
        self.second.tag(["shared"])

        db_tag = tag.Tag.find(name="shared")
        assert db_tag is not None
        self.assertEqual(db_tag.count, 1)
        self.assertEqual([t.name for t in self.stored().tags], ["shared"])

    def test_context_survives_a_stale_expire_tags(self) -> None:
        self.first.add_context("FeedA", {"seen": 1})
        self.second.expire_tags()

        self.assertEqual(
            [context["source"] for context in self.stored().context], ["FeedA"]
        )

    def test_the_writer_retried_sees_the_stored_state(self) -> None:
        self.first.add_context("FeedA", {"seen": 1})
        saved = self.second.add_context("FeedB", {"seen": 1})

        for obj in (saved, self.second):
            with self.subTest(obj="returned" if obj is saved else "self"):
                self.assertCountEqual(
                    [context["source"] for context in obj.context], ["FeedA", "FeedB"]
                )
        # And it can keep writing without reloading.
        self.second.tag(["feed-b"])
        self.assertEqual([t.name for t in self.stored().tags], ["feed-b"])

    def test_an_object_without_a_revision_starts_from_the_stored_one(self) -> None:
        # An event message carries the object as it was when it was saved,
        # without its revision.
        snapshot = ipv4.IPv4(**self.first.model_dump())
        self.first.tag(["feed-a"])
        snapshot.add_context("EventTask", {"seen": 1})

        stored = self.stored()
        self.assertEqual([t.name for t in stored.tags], ["feed-a"])
        self.assertEqual([c["source"] for c in stored.context], ["EventTask"])

    def test_replace_context_keeps_the_other_writers_tags(self) -> None:
        self.first.tag(["feed-a"])
        self.second.replace_context([{"source": "Analyst", "note": "checked"}])

        stored = self.stored()
        self.assertEqual(stored.context, [{"source": "Analyst", "note": "checked"}])
        self.assertEqual([t.name for t in stored.tags], ["feed-a"])

    def test_update_context_builds_on_the_stored_entry(self) -> None:
        def seen_once_more(current: dict | None) -> dict:
            return {"total_seen": (current or {}).get("total_seen", 0) + 1}

        self.first.update_context("Package", seen_once_more)
        self.second.update_context("Package", seen_once_more)

        self.assertEqual(
            self.stored().context, [{"source": "Package", "total_seen": 2}]
        )

    def test_replace_tags_keeps_the_other_writers_context(self) -> None:
        self.first.add_context("FeedA", {"seen": 1})
        now = datetime.datetime.now(datetime.timezone.utc)
        self.second.replace_tags(
            [model.YetiTagInstance(name="restored", last_seen=now, fresh=True)]
        )

        stored = self.stored()
        self.assertEqual([t.name for t in stored.tags], ["restored"])
        self.assertEqual([c["source"] for c in stored.context], ["FeedA"])

    def test_clear_tags_uncounts_the_stored_tags(self) -> None:
        self.first.tag(["feed-a"])
        self.second.clear_tags()

        self.assertEqual(self.stored().tags, [])
        db_tag = tag.Tag.find(name="feed-a")
        assert db_tag is not None
        self.assertEqual(db_tag.count, 0)
