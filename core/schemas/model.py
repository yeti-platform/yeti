from typing import Any

from pydantic import BaseModel, computed_field

from core.schemas.graph import TagRelationship


class YetiModel(BaseModel):
    _exclude_overwrite: list[str] = list()
    __id: str | None = None
    total_links: int | None = None
    aggregated_links: list[dict[str, Any]] | None = None

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", data.get("id", None))

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id


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
