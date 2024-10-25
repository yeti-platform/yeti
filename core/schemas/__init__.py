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


def register_schemas_types(
    schema_root_type: str, schema_enum: aenum, type_pattern: re.Pattern
) -> set:
    """
    Register the types of schemas from implementation files
    :param schema_root_type: The schema root type to work with
    :param schema_enum: The schema enum to extend
    :param type_pattern: The pattern to match the types in the schema implementation files
    """
    logger.info(f"Loading {schema_root_type} types")
    modules = set()
    pattern_matcher = re.compile(type_pattern)
    for schema_file in Path(__file__).parent.glob(f"{schema_root_type}/**/*.py"):
        if schema_file.stem == "__init__":
            continue
        if schema_file.parent.stem == schema_root_type:
            module_name = f"core.schemas.{schema_root_type}.{schema_file.stem}"
        elif schema_file.parent.stem == "private":
            module_name = f"core.schemas.{schema_root_type}.private.{schema_file.stem}"
        with open(schema_file, "r") as f:
            content = f.read()
        for schema_type in pattern_matcher.findall(content):
            if schema_type not in schema_enum.__members__:
                logger.debug(
                    f"Adding observable type <{schema_type}> to {schema_enum.__name__} enum"
                )
                if schema_root_type == "entities":
                    aenum.extend_enum(
                        schema_enum, schema_type, schema_type.replace("_", "-")
                    )
                else:
                    aenum.extend_enum(schema_enum, schema_type, schema_type)
                modules.add(module_name)
            else:
                logger.warning(
                    f"Observable type {schema_type} defined in <{module_name}> already exists"
                )
    return modules


def register_schema_classes(base_module, base_class, modules: set, type_mapping: dict):
    """
    Register the schemas from the implementation files
    :param base_module: The schema root type to work with
    :param base_class: base class that the schema class should inherit from
    :param modules: The modules to register
    :param type_mapping: schema type mapping to update
    """
    logger.info(f"Registering {base_module.__name__} classes")
    for module_name in modules:
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, base_class):
                if "type" in obj.model_fields:
                    obs_type = obj.model_fields["type"].default.value
                    logger.debug(
                        f"Registering class {obj.__name__} defining type <{obs_type}>"
                    )
                    type_mapping[obs_type] = obj
                    setattr(base_module, obj.__name__, obj)


def load_entities():
    entity.TYPE_MAPPING = {"entity": entity.Entity, "entities": entity.Entity}
    types_pattern = r"Literal\[entity.EntityType.(.+?(?=\]))"
    modules = register_schemas_types("entities", entity.EntityType, types_pattern)
    register_schema_classes(entity, entity.Entity, modules, entity.TYPE_MAPPING)
    for key in entity.TYPE_MAPPING:
        if key in ["entity", "entities"]:
            continue
        cls = entity.TYPE_MAPPING[key]
        if not entity.EntityTypes:
            entity.EntityTypes = cls
        else:
            entity.EntityTypes |= cls


def load_indicators():
    indicator.TYPE_MAPPING = {
        "indicator": indicator.Indicator,
        "indicators": indicator.Indicator,
    }
    types_pattern = r"Literal\[indicator.IndicatorType.(.+?(?=\]))"
    modules = register_schemas_types(
        "indicators", indicator.IndicatorType, types_pattern
    )
    register_schema_classes(
        indicator, indicator.Indicator, modules, indicator.TYPE_MAPPING
    )
    for key in indicator.TYPE_MAPPING:
        if key in ["indicator", "indicators"]:
            continue
        cls = indicator.TYPE_MAPPING[key]
        if not indicator.IndicatorTypes:
            indicator.IndicatorTypes = cls
        else:
            indicator.IndicatorTypes |= cls


def load_observables():
    observable.TYPE_MAPPING = {
        "observable": observable.Observable,
        "observables": observable.Observable,
    }
    if "guess" not in observable.ObservableType.__members__:
        aenum.extend_enum(observable.ObservableType, "guess", "guess")
    type_pattern = r"Literal\[observable.ObservableType.(.+?(?=\]))"
    modules = register_schemas_types(
        "observables", observable.ObservableType, type_pattern
    )
    register_schema_classes(
        observable, observable.Observable, modules, observable.TYPE_MAPPING
    )
    for key in observable.TYPE_MAPPING:
        if key in ["observable", "observables"]:
            continue
        cls = observable.TYPE_MAPPING[key]
        if not observable.ObservableTypes:
            observable.ObservableTypes = cls
        else:
            observable.ObservableTypes |= cls


load_observables()
load_entities()
load_indicators()

message.EventMessage.model_rebuild()
