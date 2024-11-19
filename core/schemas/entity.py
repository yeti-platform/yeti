import datetime
from enum import Enum
from typing import ClassVar, List, Literal

from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiTagModel


# Forward declarations
# They are then populated by the load_entities function in __init__.py
class EntityType(str, Enum): ...


EntityTypes = ()
TYPE_MAPPING = {}


class Entity(YetiTagModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = ["related_observables_count"]
    _collection_name: ClassVar[str] = "entities"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["entity"] = "entity"

    name: str = Field(min_length=1)
    description: str = ""
    context: list[dict] = []
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)

    @computed_field(return_type=Literal["entity"])
    @property
    def root_type(self):
        return self._root_type

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


def create(*, name: str, type: str, **kwargs) -> "EntityTypes":
    """
    Create an entity of the given type without saving it to the database.

    type is a string representing the type of entity to create.
    If the type is not valid, a ValueError is raised.

    kwargs must contain "name" fields and will be handled by
    pydantic.
    """
    if type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid entity type")
    return TYPE_MAPPING[type](name=name, **kwargs)


def save(*, name: str, type: str, tags: List[str] = None, **kwargs):
    indicator_obj = create(name=name, type=type, **kwargs).save()
    if tags:
        indicator_obj.tag(tags)
    return indicator_obj


def find(*, name: str, **kwargs) -> "EntityTypes":
    return Entity.find(name=name, **kwargs)
