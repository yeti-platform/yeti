from pydantic import BaseModel, computed_field

from core.schemas.graph import RoleRelationship, TagRelationship


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

    def get_acls(self) -> None:
        """Returns the permissions assigned to a user.

        Args:
            user: The user to check permissions for.
        """
        vertices, paths, total = self.neighbors(
            graph="acls", direction="inbound", max_hops=2
        )
        for path in paths:
            for edge in path:
                if edge.target == self.extended_id:
                    identity = vertices[edge.source]
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
