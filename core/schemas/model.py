import datetime
import re
import unicodedata
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any, ClassVar, Self

from arango.exceptions import DocumentRevisionError
from pydantic import BaseModel, TypeAdapter, computed_field

from core.events import message
from core.events.producer import producer
from core.schemas.graph import RoleRelationship

if TYPE_CHECKING:
    from core.schemas import dfiq, entity, indicator, observable, rbac, user
    from core.schemas.graph import RelationshipTypes
    from core.schemas.tag import Tag

# Turns a context dict into the JSON form save() writes to the database.
_CONTEXT_ADAPTER = TypeAdapter(dict)


class YetiBaseModel(BaseModel):
    _exclude_overwrite: list[str] = list()
    __id: str | None = None
    # The stored document's revision when this object was loaded or saved.
    _rev: str | None = None

    _TIMELINE_IGNORE_FIELDS: ClassVar[set[str]] = {"modified"}

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", data.get("id", None))
        self._rev = data.get("_rev")

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    if TYPE_CHECKING:
        # These are provided at runtime by database_arango.ArangoYetiConnector,
        # which every persisted schema type mixes in. They are declared here
        # (type-check time only) so type checkers can resolve the calls the
        # model mixins below make on `self`. Non-persisted models such as
        # YetiTagInstance never call them.
        def save(self, *args: Any, **kwargs: Any) -> Self: ...

        def delete(self, *args: Any, **kwargs: Any) -> None: ...

        @classmethod
        def get(cls, id: str) -> Self | None: ...

        def neighbors(
            self, *args: Any, **kwargs: Any
        ) -> tuple[
            dict[
                str,
                "observable.ObservableTypes | entity.EntityTypes | indicator.IndicatorTypes | Tag | dfiq.DFIQTypes | user.User | rbac.Group",
            ],
            list[list["RelationshipTypes"]],
            int,
        ]: ...

        @property
        def extended_id(self) -> str: ...

    # Fields that feeds, analytics and users change at the same time, each by
    # changing the loaded object and saving it back.
    _SHARED_FIELDS: ClassVar[tuple[str, ...]] = ("context", "tags")
    _CHANGE_MAX_ATTEMPTS: ClassVar[int] = 10

    def _change_and_save(self, change: Callable[[Self], None]) -> Self:
        """Applies *change* to this object, then saves it.

        If another writer saved the object since it was loaded, the save is
        refused, *change* is applied again to the stored context and tags, and
        the save is retried. Without this, the second writer would overwrite
        the first one's context and tags with its own stale copy. Other fields
        keep this object's values, as with save().
        """
        shared = [
            field for field in self._SHARED_FIELDS if field in type(self).model_fields
        ]

        def from_stored(stored: Self) -> Self:
            copy = self.model_copy(
                update={field: getattr(stored, field) for field in shared}
            )
            copy._rev = stored._rev
            return copy

        target = self
        if self.id and self._rev is None:
            # Nothing to check the save against, e.g. an object rebuilt from an
            # event message, so start from the stored object.
            stored = type(self).get(self.id)
            if stored is not None:
                target = from_stored(stored)
        for attempt in range(self._CHANGE_MAX_ATTEMPTS):
            change(target)
            try:
                saved = target.save(check_rev=True)
            except DocumentRevisionError:
                stored = type(self).get(self.id) if self.id else None
                if stored is None or attempt == self._CHANGE_MAX_ATTEMPTS - 1:
                    raise
                target = from_stored(stored)
                continue
            if target is not self:
                # The write started from the stored object, so this one now
                # lags behind what was saved.
                for field in shared:
                    setattr(self, field, getattr(saved, field))
                self._rev = saved._rev
            return saved
        raise AssertionError("unreachable")

    def semantic_documents(self) -> list[tuple[str, str]]:
        """Returns the texts to embed for semantic search, as (suffix, text).

        One object can produce several documents. That matters because an
        embedding encodes a single meaning: concatenating everything an object
        knows into one text yields a vector sitting at the average of those
        topics, matching none of them well. Embedding models also truncate --
        the default one silently cuts at roughly 110 words -- so a long
        combined document mostly gets discarded anyway.

        The suffix distinguishes an object's documents from each other; the
        indexer combines it with the object's extended_id to form the vector's
        id, and search groups the results back per object. Overrides should
        keep each document focused on one thing and return "self" first.
        """
        parts = []
        for label, field in (("Name", "name"), ("Value", "value")):
            value = getattr(self, field, None)
            if value:
                parts.append(f"{label}: {value}")

        description = getattr(self, "description", None)
        if description:
            parts.append(f"Description: {description}")

        tags = getattr(self, "tags", None) or getattr(self, "dfiq_tags", None) or []
        tag_names = [getattr(t, "name", None) or str(t) for t in tags]
        if tag_names:
            parts.append(f"Tags: {', '.join(tag_names)}")

        return [("self", "\n".join(parts))]


class YetiContextModel(YetiBaseModel):
    context: list[dict] = []

    def add_context(
        self,
        source: str,
        context: dict,
        skip_compare: set = set(),
        overwrite: bool = False,
    ):
        """Adds context to a Yeti object.

        Args:
            source: The source of the context.
            context: The context to add.
            skip_compare: Fields to skip when comparing context.
            overwrite: Whether to overwrite existing context regardless of comparison.
        """
        context["source"] = source
        # Compare and store the context in the form it has once saved. Feeds
        # pass datetime / pandas Timestamp / NaN values, which come back from
        # the database as ISO strings / None; compared raw, an identical
        # context never matches the reloaded entry, so a copy is appended
        # every time the same item is processed again.
        context = _CONTEXT_ADAPTER.dump_python(context, mode="json")
        compare_fields = set(context.keys()) - skip_compare - {"source"}

        temp_context = {key: context.get(key) for key in compare_fields}

        def change(obj: Self) -> None:
            found_idx = -1
            for idx, db_context in enumerate(list(obj.context)):
                if db_context["source"] != source:
                    continue
                if overwrite:
                    found_idx = idx
                    break
                temp_db = {key: db_context.get(key) for key in compare_fields}

                if temp_db == temp_context:
                    found_idx = idx
                    break

            if found_idx != -1:
                obj.context[found_idx] = context
            else:
                obj.context.append(context)

        return self._change_and_save(change)

    def delete_context(self, source: str, context: dict, skip_compare: set = set()):
        """Deletes context from an observable."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}

        def change(obj: Self) -> None:
            for idx, db_context in enumerate(list(obj.context)):
                if db_context["source"] != source:
                    continue
                for field in compare_fields:
                    if db_context.get(field) != context.get(field):
                        break
                else:
                    del obj.context[idx]
                    break

        return self._change_and_save(change)

    def replace_context(self, context: list[dict]) -> Self:
        """Replaces all of the object's context with *context*."""

        def change(obj: Self) -> None:
            obj.context = list(context)

        return self._change_and_save(change)

    def update_context(
        self, source: str, update: Callable[[dict | None], dict]
    ) -> Self:
        """Sets the context entry from *source* to what *update* returns.

        *update* gets the entry stored for *source*, or None, so that it can
        build on it, e.g. to count sightings. Unlike add_context, the object
        keeps at most one entry from *source*. *update* may be called more than
        once, so it must not change anything itself.
        """

        def change(obj: Self) -> None:
            for idx, entry in enumerate(obj.context):
                if entry["source"] == source:
                    obj.context[idx] = _context_entry(source, update(entry))
                    return
            obj.context.append(_context_entry(source, update(None)))

        return self._change_and_save(change)


def _context_entry(source: str, context: dict) -> dict:
    """*context* from *source*, in the form it has once saved."""
    return _CONTEXT_ADAPTER.dump_python({**context, "source": source}, mode="json")


class YetiAclModel(YetiBaseModel):
    _acls: dict[str, RoleRelationship] = {}

    def __init__(self, **data):
        super().__init__(**data)
        for name, value in data.get("acls", {}).items():
            self._acls[name] = RoleRelationship(**value)

    @computed_field(return_type=dict[str, RoleRelationship])
    @property
    def acls(self):
        return self._acls

    def get_acls(self, direct=False) -> None:
        """Returns the permissions assigned to a user.
        Args:
            user: The user to check permissions for.
        """
        # Avoid circular dependency (rbac/user both import from this module).
        from core.schemas import rbac, user

        vertices, paths, total = self.neighbors(
            graph="acls", direction="inbound", max_hops=1 if direct else 2
        )
        for path in paths:
            source = path[-1].source  # inbound, so source is last.
            for edge in path:
                if not isinstance(edge, RoleRelationship):
                    continue
                if edge.target == self.extended_id:
                    identity = vertices[source]
                    if isinstance(identity, rbac.Group):
                        self._acls[identity.name] = edge
                    if isinstance(identity, user.User):
                        self._acls[identity.username] = edge


class YetiModel(YetiBaseModel):
    total_links: int | None = None
    aggregated_links: dict[str, dict[str, int]] | None = None


class YetiTagInstance(YetiBaseModel):
    name: str
    last_seen: datetime.datetime
    expires: datetime.datetime | None = None
    fresh: bool


def _fold_accent(char: str) -> str:
    """A Latin letter without its accent, or the character unchanged.

    Folding only when the result is ASCII matters: decomposing and dropping
    combining marks is how 'é' becomes 'e', but in other scripts the mark is
    part of the letter, and dropping it turns Japanese 'ガ' into 'カ' or
    Cyrillic 'й' into 'и' -- different words.
    """
    base = "".join(
        c for c in unicodedata.normalize("NFKD", char) if not unicodedata.combining(c)
    )
    return base if base and base.isascii() else char


def normalize_name(tag_name: str) -> str:
    """Normalizes a tag name, keeping letters and digits in every script.

    Compatibility forms are folded (fullwidth letters, superscript digits),
    Latin accents are dropped, the name is lower-cased, runs of whitespace
    become "_", and anything that is not a letter, combining mark, digit or one
    of "_.:-" is removed.
    """
    tag_name = unicodedata.normalize("NFKC", tag_name)
    tag_name = "".join(_fold_accent(c) for c in tag_name).strip().lower()
    tag_name = re.sub(r"\s+", "_", tag_name)
    return "".join(
        c for c in tag_name if c in "_.:-" or unicodedata.category(c)[0] in "LMN"
    )


class YetiTagModel(YetiBaseModel):
    tags: list[YetiTagInstance] = []

    def delete(self, all_versions: bool = False):
        super().delete(all_versions=all_versions)

    def tag(
        self,
        tags: Iterable[str],
        clear: bool = False,
        normalized: bool = True,
        expiration: datetime.timedelta | None = None,
    ):
        """Adds or updates tags on an object.

        Includes options for normalization, expiration, and clearing existing tags.

        Args:
            tags: A list or iterable of tag names to be added or updated.
                If a single string is provided, it will be converted to a list.
            clear: If True, clears all existing tags before adding the new ones.
                Defaults to False.
            normalized: If True, normalizes the tag names using `normalize_name`.
                Defaults to True.
            expiration: Specifies the expiration time for the tags.
                If not provided, the default expiration for each tag is used.

        Raises:
            RuntimeError: If an empty tag name is encountered after normalization.

        Returns:
            self: The updated object with the new or modified tags.
        """
        from core.schemas import tag

        if isinstance(tags, str):  # common strings are also technically iterables.
            tags = [tags]

        actual_tags = []
        for tag_name in tags:
            new_tag_name = tag_name.strip()
            if normalized:
                new_tag_name = normalize_name(new_tag_name)
            if not new_tag_name:
                raise RuntimeError(
                    f"Cannot tag object with empty tag: '{new_tag_name}' -> '{tag_name}'"
                )
            actual_tags.append(new_tag_name)

        db_tags = []
        for tag_name in actual_tags:
            db_tag = tag.Tag.find_replacing(tag_name)

            # Attempt to find actual tag
            if not db_tag:
                db_tag = tag.Tag.find(name=tag_name)
                if not db_tag:
                    db_tag = tag.Tag(name=tag_name).save()

            expiration = expiration or db_tag.default_expiration
            db_tags.append((db_tag, expiration))

        # What the saved attempt found: the tags the object had, and the ones
        # this call added rather than refreshed.
        old_tags: list[str] = []
        added: set[str] = set()

        def change(obj: Self) -> None:
            old_tags[:] = [tag.name for tag in obj.tags]
            added.clear()
            if clear:
                obj.tags = []
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            for db_tag, tag_expiration in db_tags:
                for tag_instance in obj.tags:
                    if tag_instance.name == db_tag.name:
                        tag_instance.last_seen = now
                        tag_instance.expires = now + tag_expiration
                        tag_instance.fresh = True
                        break
                else:
                    obj.tags.append(
                        YetiTagInstance(
                            name=db_tag.name,
                            last_seen=now,
                            expires=now + tag_expiration,
                            fresh=True,
                        )
                    )
                    added.add(db_tag.name)

        self._change_and_save(change)

        # Counted and announced after the save, so that a retried save does
        # not count or announce a tag twice.
        extra_tags = set()
        for db_tag, _ in db_tags:
            if db_tag.name in added:
                added.discard(db_tag.name)
                db_tag.increment_count(1)
                action = message.EventType.new
            else:
                action = message.EventType.update

            producer.publish_event(
                message.TagEvent(
                    type=action,
                    tagged_object=self,
                    tag_object=db_tag,
                )
            )

            extra_tags |= set(db_tag.produces)

        extra_tags = extra_tags - set(tags) - set(tag.name for tag in self.tags)
        if extra_tags:
            self.tag(list(extra_tags), clear=False)

        removed_tags = set(old_tags) - set(actual_tags)
        if clear:
            for tag_name in removed_tags:
                removed_tag = tag.Tag.find(name=tag_name)
                if not removed_tag:
                    continue
                removed_tag.increment_count(-1)

                producer.publish_event(
                    message.TagEvent(
                        type=message.EventType.delete,
                        tagged_object=self,
                        tag_object=removed_tag,
                    )
                )

        return self

    def expire_tag(self, name: str):
        """Expire a tag in an object.

        Args:
            name: The name of the tag to expire.
        """

        def change(obj: Self) -> None:
            for tag in obj.tags:
                if tag.name == name:
                    tag.expires = datetime.datetime.now(tz=datetime.timezone.utc)
                    tag.fresh = False
                    break

        self._change_and_save(change)

    def expire_tags(self, now: datetime.datetime | None = None):
        """Expire all tags in an object if the expiration date is due."""
        if not now:
            now = datetime.datetime.now(tz=datetime.timezone.utc)

        def change(obj: Self) -> None:
            for tag in obj.tags:
                if tag.expires is None:
                    continue
                tag.fresh = tag.expires > now

        self._change_and_save(change)

    def replace_tags(self, tags: list[YetiTagInstance]) -> Self:
        """Replaces the object's tags with *tags*, as they are.

        Tag counts and tag events are left alone: this restores tags, e.g. in a
        migration, rather than tagging the object.
        """

        def change(obj: Self) -> None:
            obj.tags = list(tags)

        return self._change_and_save(change)

    def get_tags(self):
        return {tag.name: tag for tag in self.tags}

    def clear_tags(self):
        """Clear all tags in an object."""
        from core.schemas import tag

        cleared: list[str] = []

        def change(obj: Self) -> None:
            cleared[:] = [obj_tag.name for obj_tag in obj.tags]
            obj.tags = []

        self._change_and_save(change)
        for name in cleared:
            db_tag = tag.Tag.find(name=name)
            if db_tag:
                db_tag.increment_count(-1)
