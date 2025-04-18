from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, computed_field

from core.schemas.graph import RoleRelationship, TagRelationship

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


class YetiTagModel(YetiModel):
    _tags: dict[str, TagRelationship] = {}

    def __init__(self, **data):
        super().__init__(**data)
        for tag_name, value in data.get("tags", {}).items():
            self._tags[tag_name] = TagRelationship(**value)

    @computed_field(return_type=dict[str, TagRelationship])
    @property
    def tags(self):
        return self._tags

    def get_tags(self) -> list[tuple[TagRelationship, "Tag"]]:
        """Returns the tags linked to this object.

        Returns:
          A list of tuples (TagRelationship, Tag) representing each tag linked
          to this object.
        """
        from core.schemas.graph import TagRelationship
        from core.schemas.tag import Tag

        tag_aql = """
            for v, e, p IN 1..1 OUTBOUND @extended_id GRAPH tags
            OPTIONS {uniqueVertices: "path"}
            RETURN p
        """
        tag_paths = self._db.aql.execute(
            tag_aql, bind_vars={"extended_id": self.extended_id}
        )
        if tag_paths.empty():
            return []
        relationships = []
        self._tags = {}
        for path in tag_paths:
            tag_data = Tag.load(path["vertices"][1])
            edge_data = path["edges"][0]
            edge_data["__id"] = edge_data.pop("_id")
            tag_relationship = TagRelationship.load(edge_data)
            relationships.append((tag_relationship, tag_data))
            self._tags[tag_data.name] = tag_relationship
        return relationships
