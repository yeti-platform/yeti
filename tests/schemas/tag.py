import concurrent.futures
import datetime
import unittest
from typing import Optional

from core import database_arango
from core.schemas import model, observable
from core.schemas.observables import hostname
from core.schemas.tag import Tag


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.obs1 = hostname.Hostname(value="test1.com").save()
        self.obs2 = hostname.Hostname(value="test2.com").save()

    def test_tag_create(self) -> None:
        """Test that a tag can be created"""
        tag = Tag(name="test", description="test-desc").save()
        self.assertEqual(tag.name, "test")
        self.assertEqual(tag.description, "test-desc")
        self.assertIsNotNone(tag.id)

    def test_tags_persist(self) -> None:
        """Test that ObservableTags persist in the database."""
        self.obs1.tag(["test"])
        self.obs1.save()
        obs = observable.find(value="test1.com")
        assert obs is not None
        self.assertEqual(len(obs.tags), 1)

        self.assertEqual(obs.tags[0].name, "test")
        self.assertEqual(obs.tags[0].fresh, True)

    def test_tag_updates_count(self) -> None:
        """Test that the count of a tag is updated when a tag is added
        to an observable."""
        tag = Tag(name="test").save()
        tag = Tag(name="test2").save()
        self.assertEqual(tag.count, 0)
        self.obs1.tag(["test", "test2"])
        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, 1)
        fresh_tag = Tag.find(name="test2")
        self.assertEqual(fresh_tag.count, 1)

    def test_untag_updates_count(self) -> None:
        """Test that the count of a tag is updated when a tag is removed
        from an observable."""
        Tag(name="test").save()
        self.obs1.tag(["test"])
        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, 1)
        self.obs1.tag(["other"], clear=True)
        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, 0)

    def test_concurrent_tag_same_tag_count_is_atomic(self) -> None:
        """Concurrently tagging different objects with the same tag name must
        accumulate the count correctly, not lose updates to a racy
        read-modify-write save()."""
        concurrent_calls = 20
        Tag(name="test").save()
        observables = [
            hostname.Hostname(value=f"concurrent{i}.com").save()
            for i in range(concurrent_calls)
        ]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=concurrent_calls
        ) as executor:
            list(executor.map(lambda obs: obs.tag(["test"]), observables))

        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, concurrent_calls)

    def test_tag_update_delete_count(self) -> None:
        """Test that the count of a tag is updated when a tag is deleted
        from an observable."""
        Tag(name="test").save()
        self.obs1.tag(["test"])
        self.obs1.delete()
        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, 0)

    def test_tag_is_created(self) -> None:
        """Test that a tag is created when it is added to an observable."""
        self.obs1.tag(["test"])
        tags = list(Tag.list())
        self.assertEqual(len(list(tags)), 1)
        self.assertEqual(tags[0].name, "test")

    def test_tag_input_type(self):
        """Test that tags input is of type list, set or tuple."""

        self.obs1.tag("tag")
        self.obs1.tag(["tag2"])
        self.assertIn("tag", {tag.name for tag in self.obs1.tags})
        self.assertIn("tag2", {tag.name for tag in self.obs1.tags})

    def test_tag_is_overwritten(self) -> None:
        """Test that a tag is overwritten when it is added to an observable."""
        self.obs1.tag(["test"])
        self.obs1.tag(["test"])
        tags = list(Tag.list())
        self.assertEqual(len(list(tags)), 1)
        self.assertEqual(tags[0].name, "test")

    def test_tag_expiration(self) -> None:
        """Test that a tag can be expired and it becomes fresh if tagged again."""
        self.obs1.tag(["test"])
        self.obs1.expire_tag("test")
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertEqual(tag_instance.fresh, False)

        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertEqual(tag_instance.fresh, True)

    def test_tag_manual_expiration_date(self) -> None:
        """Test that a tag's expiration date takes in the manualy specified value."""
        self.obs1.tag(["test"], expiration=datetime.timedelta(minutes=5))
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertIsNotNone(tag_instance.expires)
        self.assertGreater(
            tag_instance.expires,
            tag_instance.last_seen + datetime.timedelta(minutes=2),
        )
        self.assertLess(
            tag_instance.expires,
            tag_instance.last_seen + datetime.timedelta(minutes=6),
        )

    def test_default_tag_expiration(self) -> None:
        """Test that a tag's expiration date tages the tag's default."""
        Tag(name="test", default_expiration=datetime.timedelta(days=365)).save()
        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_relationship = tags["test"]
        self.assertIsNotNone(tag_relationship.expires)
        self.assertGreater(
            tag_relationship.expires,
            tag_relationship.last_seen + datetime.timedelta(days=364),
        )
        self.assertLess(
            tag_relationship.expires,
            tag_relationship.last_seen + datetime.timedelta(days=366),
        )

    def test_clear_tags(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test"])
        self.obs1.clear_tags()
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 0)

    def test_tag_strict(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test1", "test2", "test3"])
        self.obs1.tag(["test"], clear=True)
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)

    def test_tag_replaces(self) -> None:
        """Test that a tag can replace another tag."""
        tag = Tag(name="testst").save()
        newtag = Tag(name="test").save()
        newtag.replaces = ["testst"]
        newtag = newtag.save()

        self.obs1.tag(["testst"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        self.assertEqual(tags["test"].name, "test")

        tag = Tag.find(name="testst")
        assert tag is not None
        self.assertEqual(tag.count, 0)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

    def test_tag_replaces_multiple_names(self) -> None:
        """A tag that replaces several names must be applied for each of them,
        and none of the replaced names may be recreated as a tag."""
        Tag(name="target", replaces=["alias_a", "alias_b"]).save()

        self.obs1.tag(["alias_a"])
        self.obs2.tag(["alias_b"])

        self.assertEqual(list(self.obs1.get_tags()), ["target"])
        self.assertEqual(list(self.obs2.get_tags()), ["target"])
        self.assertIsNone(Tag.find(name="alias_a"))
        self.assertIsNone(Tag.find(name="alias_b"))
        target = Tag.find(name="target")
        assert target is not None
        self.assertEqual(target.count, 2)

    def test_tag_absorb_permanent_replaces_absorbed_names(self) -> None:
        """After a permanent absorb of two tags, tagging with either absorbed
        name must apply the absorbing tag instead of recreating the old one."""
        target = Tag(name="target").save()
        Tag(name="old_a").save()
        Tag(name="old_b", replaces=["old_b_typo"]).save()
        target.absorb(["old_a", "old_b"], permanent=True)

        self.obs1.tag(["old_a"])
        self.obs2.tag(["old_b"])
        obs3 = hostname.Hostname(value="test3.com").save()
        obs3.tag(["old_b_typo"])

        for obs in (self.obs1, self.obs2, obs3):
            self.assertEqual(list(obs.get_tags()), ["target"], obs.value)
        for name in ("old_a", "old_b", "old_b_typo"):
            self.assertIsNone(Tag.find(name=name), name)
        target = Tag.find(name="target")
        assert target is not None
        self.assertEqual(target.count, 3)

    def test_tag_produces(self) -> None:
        """Test that a tag can produce another tag."""
        Tag(name="test", produces=["test_extended"]).save()

        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 2)
        tag_names = [tag.name for tag in tags.values()]
        self.assertEqual(sorted(tag_names), sorted(["test", "test_extended"]))

        tag = Tag.find(name="test_extended")
        assert tag is not None
        self.assertEqual(tag.count, 1)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

    def test_tag_recursion_loop(self) -> None:
        """Test that a tag can produce multiple tags."""
        Tag(name="test1", produces=["test2"]).save()
        Tag(name="test2", produces=["test3"]).save()
        Tag(name="test3", produces=["test1"]).save()

        self.obs1.tag(["test1"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 3)
        tag_names = [tag.name for tag in tags.values()]
        self.assertEqual(sorted(tag_names), sorted(["test1", "test2", "test3"]))

    def test_tag_absorb_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1", produces=["tag_prod1"], count=10).save()
        Tag(name="old_tag_2", replaces=["typod_tag"], produces=["tag_prod2"]).save()
        merge_count = tag.absorb(["old_tag_1", "old_tag_2"], permanent=True)

        self.assertEqual(merge_count, 2)
        self.assertEqual(tag.count, 10)
        self.assertEqual(
            sorted(tag.replaces), sorted(["old_tag_1", "old_tag_2", "typod_tag"])
        )
        self.assertEqual(sorted(tag.produces), sorted(["tag_prod1", "tag_prod2"]))

        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNotNone(Tag.find(name="test"))

    def test_tag_absorb_non_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1", produces=["tag_prod1"], count=10).save()
        Tag(name="old_tag_2", replaces=["typod_tag"], produces=["tag_prod2"]).save()

        merge_count = tag.absorb(["old_tag_1", "old_tag_2"], permanent=False)

        self.assertEqual(merge_count, 2)
        self.assertEqual(tag.replaces, [])
        self.assertEqual(tag.produces, [])
        self.assertEqual(tag.count, 10)

        self.assertIsNotNone(Tag.find(name="old_tag_1"))
        self.assertIsNotNone(Tag.find(name="old_tag_2"))
        self.assertIsNotNone(Tag.find(name="test"))

        tag2 = Tag.find(name="old_tag_1")
        assert tag2 is not None
        self.assertEqual(tag2.count, 0)

    def test_duplicate_name(self):
        """Tests that a saving a tag with the same name will return the existing tag."""
        tag = Tag(name="test").save()
        tag2 = Tag(name="test").save()
        self.assertEqual(tag.id, tag2.id)

    def test_normalized_tag(self):
        """Tests that a tag can be normalized."""
        cases = [
            ("H@ackërS T3st", "hackers_t3st"),
            ("    SpaCesStartEnd  ", "spacesstartend"),
            ("!!Sp3cial##", "sp3cial"),
            ("Multi    Spaces   After", "multi_spaces_after"),
            ("Élévation", "elevation"),
            ("UNDER_score", "under_score"),
            ("mixCaseMix123", "mixcasemix123"),
            ("MïxedÁccénts", "mixedaccents"),
            ("123456", "123456"),
            # Letters in every script are kept; only Latin accents are folded.
            ("测试chinese", "测试chinese"),
            ("type:some-custom-type", "type:some-custom-type"),
        ]

        for cmp, (tag_non_norm, tag_norm) in enumerate(cases):
            obs = observable.save(value=f"test-{cmp}.com")
            obs.tag([tag_non_norm])
            self.assertIn(tag_norm, {tag.name for tag in obs.tags})

    def test_normalized_tag_keeps_every_script(self):
        """Non-Latin names keep their letters and the marks that belong to them,
        and a name mixing scripts is not truncated at the first non-ASCII letter."""
        cases = [
            ("狼毒草", "狼毒草"),
            ("Медведь", "медведь"),
            ("apt-медведь", "apt-медведь"),
            ("Йод", "йод"),  # the breve is part of й; dropping it gives и
            ("ガルーダ", "ガルーダ"),  # likewise the voicing mark on ガ
            ("한국", "한국"),
            ("Ελλάδα", "ελλάδα"),
            ("किताब", "किताब"),
            ("Straße", "straße"),
            ("Søren", "søren"),
            # Compatibility forms and Latin accents still fold to ASCII.
            ("Ｆｕｌｌ Width", "full_width"),
            ("x²", "x2"),
            ("İstanbul", "istanbul"),
            ("Café Noir", "cafe_noir"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(model.normalize_name(raw), expected)

    def test_non_latin_alias_does_not_cost_the_other_tags(self):
        """Feeds tag an object with all its aliases in one call. A name that
        normalized to nothing used to raise and lose every tag in the call."""
        obs = observable.save(value="gelsemium.example.com")
        obs.tag(["Gelsemium", "狼毒草"])
        self.assertEqual({tag.name for tag in obs.tags}, {"gelsemium", "狼毒草"})
