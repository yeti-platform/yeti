# TODO Observable value normalization

import datetime
import io
import os
import tempfile

# Data Schema
# Dynamically register all observable types
from enum import Enum

# from enum import Enum, EnumMeta
from typing import IO, ClassVar, List, Literal, Tuple

import requests
from bs4 import BeautifulSoup
from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now, refang
from core.schemas.model import YetiTagModel


# Forward declarations
# They are then populated by the load_observables function in __init__.py
class ObservableType(str, Enum): ...


ObservableTypes = ()
TYPE_MAPPING = {}
FileLikeObject = str | os.PathLike | IO | tempfile.SpooledTemporaryFile


class Observable(YetiTagModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
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

    @computed_field
    def is_valid(self) -> bool:
        valid = True
        if hasattr(self, "validator"):
            try:
                valid = self.validator(self.value)
            except ValueError:
                return False
        return valid

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
    value = refang(value.strip())
    for obs_type, obj in TYPE_MAPPING.items():
        if not hasattr(obj, "validator"):
            continue
        if obj.validator(value):
            return obs_type
    return None


def create(*, value: str, type: str | None = None, **kwargs) -> ObservableTypes:
    """
    Create an observable object without saving it to the database.

    value argument representing the value of the observable.

    if kwargs does not contain a "type" field, type will be automatically
    determined based on the value. If the type is not recognized, a ValueError
    will be raised.
    """
    if not type or type == "guess":
        type = guess_type(value)
        if not type:
            raise ValueError(f"Invalid type for observable '{value}'")
    elif type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid observable type")
    return TYPE_MAPPING[type](value=value, **kwargs)


def save(
    *,
    value: str,
    type: str | None = None,
    tags: List[str] = None,
    overwrite=False,
    **kwargs,
) -> ObservableTypes:
    """
    Save an observable object. If the object is already in the database, it will be updated.

    kwargs must contain a "value" field representing the of the observable.

    if kwargs does not contain a "type" field, type will be automatically
    determined based on the value. If the type is not recognized, a ValueError will be raised.

    tags is an optional list of tags to add to the observable.
    """
    observable_obj = create(value=value, type=type, **kwargs)
    db_obs = find(value=observable_obj.value, type=observable_obj.type)
    if db_obs:
        if overwrite:
            observable_obj = observable_obj.save()
        else:
            observable_obj = db_obs
    else:
        observable_obj = observable_obj.save()
    if tags:
        observable_obj.tag(tags)
    return observable_obj


def find(value: str, type: str = None) -> ObservableTypes:
    if type:
        obs = Observable.find(value=refang(value), type=type)
    else:
        obs = Observable.find(value=refang(value))
    return obs


def create_from_text(text: str) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Create a list of observables from a block of text.

    The text is split into lines and each line is used to create an observable.
    """
    unknown = list()
    observables = list()
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obs = create(value=line)
            observables.append(obs)
        except ValueError:
            unknown.append(line)
    return observables, unknown


def save_from_text(
    text: str, tags: List[str] = None
) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Save a list of observables from a block of text.

    The text is split into lines and each line is used to create and save an observable.
    """
    saved_observables = []
    observables, unknown = create_from_text(text)
    for obs in observables:
        obs = obs.save()
        if tags:
            obs.tag(tags)
        saved_observables.append(obs)
    return saved_observables, unknown


def create_from_file(file: FileLikeObject) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Create a list of observables from a block of text.

    The text is split into lines and each line is used to create an observable.
    """
    opened = False
    if isinstance(file, (str, bytes, os.PathLike)):
        f = open(file, "r", encoding="utf-8")
        opened = True
    elif isinstance(file, (io.IOBase, tempfile.SpooledTemporaryFile)):
        f = file
    else:
        raise ValueError("Invalid file type")
    observables = list()
    unknown = list()
    for line in f.readlines():
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        line = line.strip()
        if not line:
            continue
        try:
            obs = create(value=line)
            observables.append(obs)
        except ValueError:
            unknown.append(line)
    if opened:
        f.close()
    return observables, unknown


def save_from_file(
    file: FileLikeObject, tags: List[str] = None
) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Save a list of observables from a block of text.

    The text is split into lines and each line is used to create and save an observable.
    """
    observables, unknown = create_from_file(file)
    saved_observables = list()
    for obs in observables:
        obs = obs.save()
        if tags:
            obs.tag(tags)
        saved_observables.append(obs)
    return saved_observables, unknown


def create_from_url(url: str) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Create a list of observables from a URL.

    The URL is fetched and the content is split into lines. Each line is used to create an observable.
    """
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    return create_from_text(soup.get_text())


def save_from_url(
    url: str, tags: List[str] = None
) -> Tuple[List["ObservableTypes"], List[str]]:
    """
    Save a list of observables from a URL.

    The URL is fetched and the content is split into lines. Each line is used to create and save an observable.
    """
    saved_observables = []
    observables, unknown = create_from_url(url)
    for obs in observables:
        obs = obs.save()
        if tags:
            obs.tag(tags)
        saved_observables.append(obs)
    return saved_observables, unknown
