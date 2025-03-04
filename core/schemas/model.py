from typing import TYPE_CHECKING

from pydantic import BaseModel, computed_field

from core.schemas.graph import RoleRelationship, TagRelationship

if TYPE_CHECKING:
    from core.schemas.tag import Tag


class YetiBaseModel(BaseModel):
    _exclude_overwrite: list[str] = list()
    __id: str | None = None

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", data.get("id", None))

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id


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

    def get_acls(self) -> dict[str, RoleRelationship]:
        """Returns the permissions assigned to a user.

        Args:
            user: The user to check permissions for.
        """
        acl_acl = """
         WITH observables, entities, dfiq, indicators

        FOR v, e IN 1..2 inbound @extended_id acls
          OPTIONS { uniqueVertices: "path" }

        RETURN  {name: v.username || v.name, edge: e}
        """
        results = self._db.aql.execute(
            acl_acl, bind_vars={"extended_id": self.extended_id}
        )
        for r in results:
            if r["edge"]["target"] == self.extended_id:
                self._acls[r["name"]] = RoleRelationship(**r["edge"])

        return self._acls


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
