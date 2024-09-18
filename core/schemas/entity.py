import datetime
from enum import Enum
from typing import ClassVar, Literal

from pydantic import Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiTagModel


# forward declarations
class EntityType(str, Enum): ...


EntityTypes = ()
TYPE_MAPPING = {}


class Entity(YetiTagModel, database_arango.ArangoYetiConnector):
    _exclude_overwrite: list[str] = ["related_observables_count"]
    _collection_name: ClassVar[str] = "entities"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["entity"] = "entity"

    type: str
    name: str = Field(min_length=1)
    description: str = ""
    context: list[dict] = []
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)

    @computed_field(return_type=Literal["entity"])
    @property
    def root_type(self):
        return self._root_type

    @computed_field(return_type=int)
    def related_observables_count(self):
        if self.id:
            vertices, path, total = self.neighbors(
                min_hops=1, max_hops=1, target_types=["observable"]
            )
            return total
        return 0

    @classmethod
    def load(cls, object: dict) -> "EntityTypes":
        if cls._type_filter:
            loader = TYPE_MAPPING[cls._type_filter]
        elif object["type"] in TYPE_MAPPING:
            loader = TYPE_MAPPING[object["type"]]
        else:
            raise ValueError("Attempted to instantiate an undefined entity type.")
        return loader(**object)

    @classmethod
    def is_valid(cls, object: "Entity") -> bool:
        return False

    def add_context(
        self, source: str, context: dict, skip_compare: set = set()
    ) -> "Entity":  # noqa: F821
        """Adds context to an entity."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}
        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    context["source"] = source
                    self.context[idx] = context
                    break
            else:
                db_context.update(context)
                break
        else:
            context["source"] = source
            self.context.append(context)
        return self.save()
