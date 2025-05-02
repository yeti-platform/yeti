import datetime
import re
import unicodedata
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, computed_field

from core.schemas.graph import RoleRelationship

if TYPE_CHECKING:
    from core.schemas.tag import Tag


class YetiBaseModel(BaseModel):
    _exclude_overwrite: list[str] = list()
    __id: str | None = None

    _TIMELINE_IGNORE_FIELDS: ClassVar[set[str]] = {"modified"}

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", data.get("id", None))

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id


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
        compare_fields = set(context.keys()) - skip_compare - {"source"}

        found_idx = -1
        temp_context = {key: context.get(key) for key in compare_fields}

        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            if overwrite:
                found_idx = idx
                break
            temp_db = {key: db_context.get(key) for key in compare_fields}

            if temp_db == temp_context:
                found_idx = idx
                break

        context["source"] = source
        if found_idx != -1:
            self.context[found_idx] = context
        else:
            self.context.append(context)

        return self.save()

    def delete_context(self, source: str, context: dict, skip_compare: set = set()):
        """Deletes context from an observable."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}
        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    break
            else:
                del self.context[idx]
                break

        return self.save()


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
        vertices, paths, total = self.neighbors(
            graph="acls", direction="inbound", max_hops=1 if direct else 2
        )
        for path in paths:
            source = path[-1].source  # inbound, so source is last.
            for edge in path:
                if edge.target == self.extended_id:
                    identity = vertices[source]
                    if identity.root_type == "rbacgroup":
                        self._acls[identity.name] = edge
                    if identity.root_type == "user":
                        self._acls[identity.username] = edge


class YetiModel(YetiBaseModel):
    total_links: int | None = None
    aggregated_links: dict[str, dict[str, int]] | None = None


class YetiTagInstance(YetiModel):
    name: str
    last_seen: datetime.datetime
    expires: datetime.datetime | None = None
    fresh: bool


def normalize_name(tag_name: str) -> str:
    nfkd_form = unicodedata.normalize("NFKD", tag_name)
    nfkd_form.encode("ASCII", "ignore").decode("UTF-8")
    tag_name = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
    tag_name = tag_name.strip().lower()
    tag_name = re.sub(r"\s+", "_", tag_name)
    tag_name = re.sub(r"[^a-zA-Z0-9_.:-]", "", tag_name)
    return tag_name


class YetiTagModel(YetiModel):
    tags: dict[str, YetiTagInstance] = {}

    def tag(
        self,
        tags: list[str],
        strict: bool = False,
        normalized: bool = True,
        expiration: datetime.timedelta | None = None,
    ):
        """Adds or updates a tag in an object."""
        from core.schemas import tag

        if not isinstance(tags, (list, set, tuple)):
            raise ValueError("Tags must be of type list, set or tuple.")

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

        if strict:
            self.tags = {}

        extra_tags = set()
        for tag_name in actual_tags:
            replacements, _ = tag.Tag.filter({"in__replaces": [tag_name]}, count=1)

            if replacements:
                new_tag = replacements[0]
            # Attempt to find actual tag
            else:
                new_tag = tag.Tag.find(name=tag_name)
                if not new_tag:
                    new_tag = tag.Tag(name=tag_name).save()

            expiration = expiration or new_tag.default_expiration
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            self.tags[new_tag.name] = YetiTagInstance(
                name=new_tag.name,
                last_seen=now,
                expires=now + expiration,
                fresh=True,
            )

            new_tag.count += 1
            new_tag.save()

            extra_tags |= set(new_tag.produces)

        extra_tags -= set(tags)
        if extra_tags:
            self.tag(list(extra_tags))

        self.save()
        return self

    def expire_tag(self, name: str):
        """Expire a tag in an object.

        Args:
            name: The name of the tag to expire.
        """
        self.tags[name].fresh = False
        self.save()

    def expire_tags(self):
        """Expire all tags in an object if the expiration date is due."""
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for tag_instance in self.tags.values():
            if not tag_instance.expires:
                continue
            tag_instance.fresh = tag_instance.expires > now
        self.save()

    def get_tags(self):
        return self.tags

    def clear_tags(self):
        """Clear all tags in an object."""
        self.tags = {}
        self.save()
