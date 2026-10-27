"""Helper to load user-supplied ("private") schema types.

The observable/entity/indicator packages each expose a `private` subpackage
where deployments can drop in their own subtypes. Unlike the public types,
these are not known statically, so they are discovered at import time by
globbing the `private` subpackage. This is the only remaining dynamic hook in
the schema layer — public types are all registered explicitly.

The API's request and response models discriminate each family's union on the
`type` field, so every member has to declare `type` as a Literal whose values
no other member uses. `load_private_types()` refuses private types that break
the first rule, and `check_discriminator_fields()` rejects a registry that
breaks either, each naming the class and what to change.
"""

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable
from typing import Literal, TypeVar, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _declaration_hint(cls: type, field: FieldInfo | None) -> str:
    name = cls.__name__.lower()
    if field is not None and isinstance(field.default, str):
        name = field.default
    return f'`type: Literal["{name}"] = "{name}"`'


def _qualified_name(cls: type) -> str:
    return f"{cls.__module__}.{cls.__name__}"


def load_private_types(package_name: str, base_class: type[T]) -> list[type[T]]:
    """Return the schema subclasses defined in `<package_name>.private`.

    Args:
        package_name: e.g. "core.schemas.observables".
        base_class: the family base class (Observable/Entity/Indicator);
            only its subclasses that declare a `type` field are returned, and
            a subclass whose `type` is not a Literal is skipped with an error.
    """
    classes: list[type[T]] = []
    try:
        private_pkg = importlib.import_module(f"{package_name}.private")
    except ModuleNotFoundError:
        return classes

    for _, modname, _ in pkgutil.iter_modules(private_pkg.__path__):
        full_name = f"{package_name}.private.{modname}"
        try:
            module = importlib.import_module(full_name)
        except Exception:
            logger.exception(f"Failed to import private schema module {full_name}")
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__ or not issubclass(obj, base_class):
                continue
            field = getattr(obj, "model_fields", {}).get("type")
            if field is None:
                continue
            if get_origin(field.annotation) is not Literal:
                logger.error(
                    f"Not registering private type {obj.__name__} from {full_name}: "
                    f"its `type` field is annotated {field.annotation!r}, and the API "
                    f"needs a Literal to tell types apart, for example "
                    f"{_declaration_hint(obj, field)}."
                )
                continue
            logger.info(f"Registering private type {obj.__name__} from {full_name}")
            classes.append(obj)
    return classes


def check_discriminator_fields(classes: Iterable[type[BaseModel]], family: str) -> None:
    """Raise TypeError unless `classes` can form a discriminated union on `type`.

    Each class must annotate `type` as a Literal, and no two classes may share
    a Literal value. pydantic checks the same thing while building the API's
    request and response models, but its errors do not say which class to fix
    or how; this runs first, at import of the family's registry.
    """
    owners: dict[object, type[BaseModel]] = {}
    for cls in classes:
        field = cls.model_fields.get("type")
        if field is None or get_origin(field.annotation) is not Literal:
            declared = (
                "no `type` field"
                if field is None
                else f"`type` as {field.annotation!r}"
            )
            raise TypeError(
                f"{family} type {_qualified_name(cls)} declares {declared}; the API "
                f"needs a Literal to tell types apart, for example "
                f"{_declaration_hint(cls, field)}."
            )
        for value in get_args(field.annotation):
            if value in owners:
                raise TypeError(
                    f"{family} types {_qualified_name(owners[value])} and "
                    f"{_qualified_name(cls)} both declare type {value!r}; "
                    f"every type needs a value of its own."
                )
            owners[value] = cls
