from __future__ import annotations

import datetime
import io
import os
import tempfile
from enum import Enum
from typing import IO, Callable, ClassVar, List, Literal, Tuple, Union, cast

import requests
from bs4 import BeautifulSoup
from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now, refang
from core.schemas.model import YetiAclModel, YetiContextModel, YetiTagModel

# The concrete observable types, the ObservableType enum, the ObservableTypes
# union and TYPE_MAPPING are all defined statically at the bottom of this
# module (see "Static type registry"). TYPE_MAPPING must exist before the
# functions below are *called*, which is always the case at runtime.
TYPE_MAPPING: dict[str, type["Observable"]] = {}
FileLikeObject = str | os.PathLike | IO | tempfile.SpooledTemporaryFile


class Observable(
    YetiTagModel, YetiAclModel, YetiContextModel, database_arango.ArangoYetiConnector
):
    model_config = ConfigDict(str_strip_whitespace=True)
    _collection_name: ClassVar[str] = "observables"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["observable"] = "observable"

    value: str = Field(min_length=1)
    last_analysis: dict[str, datetime.datetime] = {}

    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)

    @computed_field(return_type=Literal["observable"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "ObservableTypes":  # noqa: F821
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        raise ValueError("Attempted to instantiate an undefined observable type.")

    def save(self, *args, **kwargs) -> "Observable":
        self.modified = now()
        return super().save(*args, **kwargs)

    @computed_field
    def is_valid(self) -> bool:
        valid = True
        if hasattr(self, "validator"):
            try:
                valid = cast("Callable[[str], bool]", self.validator)(self.value)
            except ValueError:
                return False
        return valid


def guess_type(value: str) -> str | None:
    """
    Guess the type of an observable based on its value.

    Returns the type if it can be guessed, otherwise None.
    """
    value = refang(value.strip())
    for obs_type, obj in TYPE_MAPPING.items():
        if not hasattr(obj, "validator"):
            continue
        if cast("Callable[[str], bool]", obj.validator)(value):
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
    tags: List[str] | None = None,
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


def find(value: str, type: str | None = None) -> ObservableTypes:
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
    text: str, tags: List[str] | None = None
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
        # The isinstance guard narrows `file` to a path, but FileLikeObject's
        # unparametrized os.PathLike doesn't match open()'s PathLike[str] overload.
        f = open(cast("str | os.PathLike[str]", file), "r", encoding="utf-8")
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
    file: FileLikeObject, tags: List[str] | None = None
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
    url: str, tags: List[str] | None = None
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


# ---------------------------------------------------------------------------
# Static type registry
#
# Every observable subtype is imported and registered explicitly below. This
# replaces the previous import-time reflection (aenum + directory globbing), so
# ObservableType / ObservableTypes / TYPE_MAPPING are visible to static type
# checkers and to FastAPI's OpenAPI generation.
#
# To add a new observable type: create the module under observables/ and add it
# both to the imports and to _OBSERVABLE_CLASSES below. tests/schemas/registry
# fails if a subtype is defined but not registered here.
# ---------------------------------------------------------------------------
from core.schemas.loader import load_private_types  # noqa: E402
from core.schemas.observables.asn import ASN  # noqa: E402
from core.schemas.observables.auth_secret import AuthSecret  # noqa: E402
from core.schemas.observables.bic import BIC  # noqa: E402
from core.schemas.observables.certificate import Certificate  # noqa: E402
from core.schemas.observables.cidr import CIDR  # noqa: E402
from core.schemas.observables.command_line import CommandLine  # noqa: E402
from core.schemas.observables.container_image import (  # noqa: E402
    ContainerImage,
    DockerImage,
)
from core.schemas.observables.email import Email  # noqa: E402
from core.schemas.observables.file import File  # noqa: E402
from core.schemas.observables.generic import Generic  # noqa: E402
from core.schemas.observables.hostname import Hostname  # noqa: E402
from core.schemas.observables.iban import IBAN  # noqa: E402
from core.schemas.observables.imphash import Imphash  # noqa: E402
from core.schemas.observables.ipv4 import IPv4  # noqa: E402
from core.schemas.observables.ipv6 import IPv6  # noqa: E402
from core.schemas.observables.ja3 import JA3  # noqa: E402
from core.schemas.observables.jarm import JARM  # noqa: E402
from core.schemas.observables.mac_address import MacAddress  # noqa: E402
from core.schemas.observables.md5 import MD5  # noqa: E402
from core.schemas.observables.mutex import Mutex  # noqa: E402
from core.schemas.observables.named_pipe import NamedPipe  # noqa: E402
from core.schemas.observables.package import Package  # noqa: E402
from core.schemas.observables.path import Path  # noqa: E402
from core.schemas.observables.registry_key import RegistryKey  # noqa: E402
from core.schemas.observables.sha1 import SHA1  # noqa: E402
from core.schemas.observables.sha256 import SHA256  # noqa: E402
from core.schemas.observables.ssdeep import Ssdeep  # noqa: E402
from core.schemas.observables.tlsh import TLSH  # noqa: E402
from core.schemas.observables.url import Url  # noqa: E402
from core.schemas.observables.user_account import UserAccount  # noqa: E402
from core.schemas.observables.user_agent import UserAgent  # noqa: E402
from core.schemas.observables.wallet import Wallet  # noqa: E402


class ObservableType(str, Enum):
    guess = "guess"
    asn = "asn"
    auth_secret = "auth_secret"
    bic = "bic"
    certificate = "certificate"
    cidr = "cidr"
    command_line = "command_line"
    container_image = "container_image"
    docker_image = "docker_image"
    email = "email"
    file = "file"
    generic = "generic"
    hostname = "hostname"
    iban = "iban"
    imphash = "imphash"
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    ja3 = "ja3"
    jarm = "jarm"
    mac_address = "mac_address"
    md5 = "md5"
    mutex = "mutex"
    named_pipe = "named_pipe"
    package = "package"
    path = "path"
    registry_key = "registry_key"
    sha1 = "sha1"
    sha256 = "sha256"
    ssdeep = "ssdeep"
    tlsh = "tlsh"
    url = "url"
    user_account = "user_account"
    user_agent = "user_agent"
    wallet = "wallet"


_OBSERVABLE_CLASSES: list[type[Observable]] = [
    ASN,
    AuthSecret,
    BIC,
    Certificate,
    CIDR,
    CommandLine,
    ContainerImage,
    DockerImage,
    Email,
    File,
    Generic,
    Hostname,
    IBAN,
    Imphash,
    IPv4,
    IPv6,
    JA3,
    JARM,
    MacAddress,
    MD5,
    Mutex,
    NamedPipe,
    Package,
    Path,
    RegistryKey,
    SHA1,
    SHA256,
    Ssdeep,
    TLSH,
    Url,
    UserAccount,
    UserAgent,
    Wallet,
]

_private_observable_classes = load_private_types("core.schemas.observables", Observable)

TYPE_MAPPING = {"observable": Observable, "observables": Observable}
for _cls in (*_OBSERVABLE_CLASSES, *_private_observable_classes):
    TYPE_MAPPING[str(_cls.model_fields["type"].default)] = cast(
        "type[Observable]", _cls
    )

# Static union for type checkers and OpenAPI. Discriminator is applied by the
# request/response models that use this alias (as before), so the generated
# schema is unchanged.
ObservableTypes = Union[
    ASN,
    AuthSecret,
    BIC,
    Certificate,
    CIDR,
    CommandLine,
    ContainerImage,
    DockerImage,
    Email,
    File,
    Generic,
    Hostname,
    IBAN,
    Imphash,
    IPv4,
    IPv6,
    JA3,
    JARM,
    MacAddress,
    MD5,
    Mutex,
    NamedPipe,
    Package,
    Path,
    RegistryKey,
    SHA1,
    SHA256,
    Ssdeep,
    TLSH,
    Url,
    UserAccount,
    UserAgent,
    Wallet,
]
# Deployments may drop extra subtypes into observables/private/; widen the
# runtime union so API response models serialize them too.
if _private_observable_classes:
    ObservableTypes = Union[(ObservableTypes, *_private_observable_classes)]
