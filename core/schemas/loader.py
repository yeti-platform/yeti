"""Helper to load user-supplied ("private") schema types.

The observable/entity/indicator packages each expose a `private` subpackage
where deployments can drop in their own subtypes. Unlike the public types,
these are not known statically, so they are discovered at import time by
globbing the `private` subpackage. This is the only remaining dynamic hook in
the schema layer — public types are all registered explicitly.
"""

import importlib
import inspect
import logging
import pkgutil

logger = logging.getLogger(__name__)


def load_private_types(package_name: str, base_class: type) -> list[type]:
    """Return the schema subclasses defined in `<package_name>.private`.

    Args:
        package_name: e.g. "core.schemas.observables".
        base_class: the family base class (Observable/Entity/Indicator);
            only its subclasses that declare a `type` field are returned.
    """
    classes: list[type] = []
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
            if (
                obj.__module__ == module.__name__
                and issubclass(obj, base_class)
                and "type" in getattr(obj, "model_fields", {})
            ):
                logger.info(f"Registering private type {obj.__name__} from {full_name}")
                classes.append(obj)
    return classes
