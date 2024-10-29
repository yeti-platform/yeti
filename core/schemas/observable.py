# TODO Observable value normalization

import datetime
import re

# Data Schema
# Dynamically register all observable types
from enum import Enum

# from enum import Enum, EnumMeta
from typing import Any, ClassVar, List, Literal

from pydantic import Field, computed_field

from core import database_arango
from core.helpers import now, refang
from core.schemas.model import YetiTagModel


# Forward declarations
# They are then populated by the load_observables function in __init__.py
class ObservableType(str, Enum): ...


ObservableTypes = ()
TYPE_MAPPING = {}


class Observable(YetiTagModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "observables"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["observable"] = "observable"

    value: str = Field(min_length=1)
    created: datetime.datetime = Field(default_factory=now)
    context: list[dict] = []
    last_analysis: dict[str, datetime.datetime] = {}

    @computed_field(return_type=Literal["observable"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "ObservableTypes":  # noqa: F821
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        raise ValueError("Attempted to instantiate an undefined observable type.")

    def add_context(
        self,
        source: str,
        context: dict,
        skip_compare: set = set(),
        overwrite: bool = False,
    ) -> "ObservableTypes":  # noqa: F821
        """Adds context to an observable."""
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

    def delete_context(
        self, source: str, context: dict, skip_compare: set = set()
    ) -> "ObservableTypes":  # noqa: F821
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


def guess_type(value: str) -> str | None:
    """
    Guess the type of an observable based on its value.

    Returns the type if it can be guessed, otherwise None.
    """
    for obs_type, obj in TYPE_MAPPING.items():
        if not hasattr(obj, "validate_value"):
            continue
        try:
            if obj.validate_value(value):
                return obs_type
        except ValueError:
            continue
    return None


def create(type: str | None = None, **kwargs) -> ObservableTypes:
    """
    Create an observable object without saving it to the database.

    kwargs must contain a "value" field representing the value of the observable.

    if kwargs does not contain a "type" field, type will be automatically
    determined based on the value. If the type is not recognized, an observable
    of type generic will be created.
    """
    if "value" not in kwargs:
        raise ValueError("name is a required field for an observable")
    value = kwargs["value"]
    if not type or type == "guess":
        type = guess_type(value)
        if not type:
            raise ValueError(f"Invalid type for observable '{value}'")
    elif type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid observable type")
    return TYPE_MAPPING[type](**kwargs)


def save(tags: List[str] = None, **kwargs) -> ObservableTypes:
    """
    Save an observable object. If the object is already in the database, it will be updated.

    kwargs must contain a "value" field representing the of the observable.

    if kwargs does not contain a "type" field, type will be automatically
    determined based on the value. If the type is not recognized, a ValueError will be raised.

    tags is an optional list of tags to add to the observable.
    """
    observable_obj = create(**kwargs).save()
    if tags:
        observable_obj.tag(tags)
    return observable_obj


def get(**kwargs) -> ObservableTypes:
    if "value" not in kwargs:
        raise ValueError("value is a required field for an observable")
    return Observable.find(**kwargs)
