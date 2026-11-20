import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from core import database_arango
from core.events.producer import producer
from core.schemas import model, observable
from core.schemas.observables import hostname
from plugins.analytics.public import expire_tags

PAST = timedelta(seconds=-10)
FUTURE = timedelta(days=1)


class ExpireTagsTest(unittest.TestCase):
    """Which observables a run loads and saves, and which it leaves alone."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        defaults = expire_tags.ExpireTags._defaults.copy()
        self.analytics = expire_tags.ExpireTags(**defaults)

    def stored(self, obs: observable.Observable) -> observable.Observable:
        assert obs.id is not None
        refreshed = observable.Observable.get(obs.id)
        assert refreshed is not None
        return refreshed

    def expired_by_run(self) -> list[str]:
        """Runs the task and returns the observables it called expire_tags() on."""
        with mock.patch.object(
            observable.Observable, "expire_tags", autospec=True
        ) as expire_tags_method:
            self.analytics.run()
        return [call.args[0].value for call in expire_tags_method.call_args_list]

    def test_tag_past_its_expiry_is_expired(self) -> None:
        """A tag still marked fresh after its expiry date is what a run is for."""
        obs = observable.save(value="expired.example.com")
        obs.tag(["feed"], expiration=PAST)

        self.assertEqual(self.expired_by_run(), [obs.value])

    def test_tag_already_marked_stale_is_left_alone(self) -> None:
        """A tag that an earlier run marked stale needs no second visit.

        Stale tags are never removed, so selecting on the expiry date alone
        picks up every observable that ever had a tag expire, on every run.
        """
        obs = observable.save(value="stale.example.com")
        obs.tag(["feed"], expiration=PAST)
        obs.expire_tags()
        self.assertFalse(self.stored(obs).tags[0].fresh)

        self.assertEqual(self.expired_by_run(), [])

    def test_tag_not_yet_expired_is_left_alone(self) -> None:
        obs = observable.save(value="current.example.com")
        obs.tag(["feed"], expiration=FUTURE)

        self.assertEqual(self.expired_by_run(), [])

    def test_tag_without_expiry_is_left_alone(self) -> None:
        """A tag whose `expires` is None never expires.

        AQL sorts null below every number, so a bare "expires < now" matches
        such a tag on every run. The tag is stored with the new observable,
        because tag() always sets an expiry date.
        """
        obs = hostname.Hostname(
            value="pinned.example.com",
            tags=[
                model.YetiTagInstance(
                    name="pinned",
                    last_seen=datetime.now(timezone.utc),
                    expires=None,
                    fresh=True,
                )
            ],
        ).save()
        self.assertIsNone(self.stored(obs).tags[0].expires)

        self.assertEqual(self.expired_by_run(), [])

    def test_stale_tag_next_to_a_renewed_tag_is_left_alone(self) -> None:
        """An observable is selected for a tag to flip, not for any old tag.

        This is an observable that one feed stopped listing a while ago and
        another feed still lists.
        """
        obs = observable.save(value="mixed.example.com")
        obs.tag(["dropped"], expiration=PAST)
        obs.expire_tags()
        obs.tag(["listed"], expiration=FUTURE)

        self.assertEqual(self.expired_by_run(), [])

    def test_observable_with_two_expired_tags_is_expired_once(self) -> None:
        obs = observable.save(value="twice.example.com")
        obs.tag(["first", "second"], expiration=PAST)

        self.assertEqual(self.expired_by_run(), [obs.value])

    def test_run_marks_only_the_expired_tag_stale(self) -> None:
        obs = observable.save(value="mixed.example.com")
        obs.tag(["dropped"], expiration=PAST)
        obs.tag(["listed"], expiration=FUTURE)
        untouched = observable.save(value="current.example.com")
        untouched.tag(["listed"], expiration=FUTURE)

        self.analytics.run()

        tags = self.stored(obs).get_tags()
        self.assertFalse(tags["dropped"].fresh)
        self.assertTrue(tags["listed"].fresh)
        self.assertTrue(self.stored(untouched).get_tags()["listed"].fresh)

    def test_run_does_not_save_an_observable_with_nothing_to_expire(self) -> None:
        """No save means no new `modified` date and no update event."""
        obs = observable.save(value="stale.example.com")
        obs.tag(["feed"], expiration=PAST)
        obs.expire_tags()
        before = self.stored(obs)

        with mock.patch.object(producer, "publish_event") as publish_event:
            self.analytics.run()

        publish_event.assert_not_called()
        self.assertEqual(self.stored(obs).modified, before.modified)

    def test_run_saves_an_observable_with_an_expired_tag_once(self) -> None:
        obs = observable.save(value="expired.example.com")
        obs.tag(["feed"], expiration=PAST)

        with mock.patch.object(producer, "publish_event") as publish_event:
            self.analytics.run()

        self.assertEqual(publish_event.call_count, 1)
        event = publish_event.call_args.args[0]
        self.assertEqual(event.yeti_object.value, obs.value)
        self.assertFalse(event.yeti_object.tags[0].fresh)

    def test_observable_deleted_during_the_run_is_skipped(self) -> None:
        """The keys are read first, so an observable can be gone at its turn."""
        gone = observable.save(value="gone.example.com")
        gone.tag(["feed"], expiration=PAST)
        kept = observable.save(value="kept.example.com")
        kept.tag(["feed"], expiration=PAST)
        real_get = observable.Observable.get
        to_delete = [gone]

        def get_after_delete(key: str) -> observable.Observable | None:
            if to_delete and key == gone.id:
                to_delete.pop().delete()
            return real_get(key)

        with mock.patch.object(
            observable.Observable, "get", side_effect=get_after_delete
        ):
            self.analytics.run()

        self.assertEqual(to_delete, [])
        self.assertFalse(self.stored(kept).tags[0].fresh)


if __name__ == "__main__":
    unittest.main()
