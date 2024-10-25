import importlib
import inspect
import logging
import re
from pathlib import Path

import aenum

from core.events import message
from core.schemas import (
    dfiq,
    entity,
    graph,
    indicator,
    observable,
    tag,
    task,
    template,
    user,
)

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)


def register_module(module_name, base_module):
    """
    Register the classes for the schema implementation files

    module_name: The module name to load
    base_module: The base module to register the classes in (entity, indicator, observable)
    """
    module = importlib.import_module(module_name)
    module_base_name = base_module.__name__.split(".")[-1]
    schema_base_class = getattr(base_module, module_base_name.capitalize())
    schema_type_mapping = getattr(base_module, "TYPE_MAPPING")
    schema_types = getattr(base_module, f"{module_base_name.capitalize()}Types", None)
    schema_enum = getattr(base_module, f"{module_base_name.capitalize()}Type")
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, schema_base_class) and "type" in obj.model_fields:
            obs_type = obj.model_fields["type"].default
            logger.info(f"Registering class {obj.__name__} defining type <{obs_type}>")
            aenum.extend_enum(schema_enum, obs_type, obs_type)
            schema_type_mapping[obs_type] = obj
            setattr(base_module, obj.__name__, obj)
            if not schema_types:
                schema_types = obj
            else:
                schema_types |= obj
            setattr(base_module, f"{module_base_name.capitalize()}Types", schema_types)


def register_classes(schema_root_type, base_module):
    """
    Register the classes for the schema root type

    schema_root_type: The schema root type to work with (entities, indicators, observables)
    base_module: The base module to register the classes in (entity, indicator, observable)
    """
    module_base_name = base_module.__name__.split(".")[-1]
    logger.info(f"Registering {module_base_name} classes")
    for schema_file in Path(__file__).parent.glob(f"{schema_root_type}/**/*.py"):
        if schema_file.stem == "__init__":
            continue
        if schema_file.parent.stem == schema_root_type:
            module_name = f"core.schemas.{schema_root_type}.{schema_file.stem}"
        elif schema_file.parent.stem == "private":
            module_name = f"core.schemas.{schema_root_type}.private.{schema_file.stem}"
        try:
            register_module(module_name, base_module)
        except Exception:
            logger.exception(f"Failed to register classes from {module_name}")


def load_entities():
    entity.TYPE_MAPPING = {"entity": entity.Entity, "entities": entity.Entity}
    register_classes("entities", entity)


def load_indicators():
    indicator.TYPE_MAPPING = {
        "indicator": indicator.Indicator,
        "indicators": indicator.Indicator,
    }
    register_classes("indicators", indicator)


def load_observables():
    observable.TYPE_MAPPING = {
        "observable": observable.Observable,
        "observables": observable.Observable,
    }
    if "guess" not in observable.ObservableType.__members__:
        aenum.extend_enum(observable.ObservableType, "guess", "guess")
    register_classes("observables", observable)


load_observables()
load_entities()
load_indicators()

message.EventMessage.model_rebuild()
