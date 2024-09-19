import importlib
import inspect
import logging
from pathlib import Path

import aenum

from core.schemas import entity, indicator, observable

logger = logging.getLogger(__name__)


def load_entities():
    logger.info("Registering entities")
    modules = dict()
    for entity_file in Path(__file__).parent.glob("entities/**/*.py"):
        if entity_file.stem == "__init__":
            continue
        logger.info(f"Registering entity type {entity_file.stem}")
        if entity_file.parent.stem == "entities":
            module_name = f"core.schemas.entities.{entity_file.stem}"
        elif entity_file.parent.stem == "private":
            module_name = f"core.schemas.entities.private.{entity_file.stem}"
        enum_value = entity_file.stem.replace("_", "-")
        if entity_file.stem not in entity.EntityType.__members__:
            aenum.extend_enum(entity.EntityType, entity_file.stem, enum_value)
        modules[module_name] = enum_value
    entity.TYPE_MAPPING = {"entity": entity.Entity, "entities": entity.Entity}
    for module_name, enum_value in modules.items():
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, entity.Entity):
                entity.TYPE_MAPPING[enum_value] = obj
                setattr(entity, obj.__name__, obj)
    for key in entity.TYPE_MAPPING:
        if key in ["entity", "entities"]:
            continue
        cls = entity.TYPE_MAPPING[key]
        if not entity.EntityTypes:
            entity.EntityTypes = cls
        else:
            entity.EntityTypes |= cls


def load_indicators():
    logger.info("Registering indicators")
    modules = dict()
    for indicator_file in Path(__file__).parent.glob("indicators/**/*.py"):
        if indicator_file.stem == "__init__":
            continue
        logger.info(f"Registering indicator type {indicator_file.stem}")
        if indicator_file.parent.stem == "indicators":
            module_name = f"core.schemas.indicators.{indicator_file.stem}"
        elif indicator_file.parent.stem == "private":
            module_name = f"core.schemas.indicators.private.{indicator_file.stem}"
        enum_value = indicator_file.stem
        if indicator_file.stem not in indicator.IndicatorType.__members__:
            aenum.extend_enum(indicator.IndicatorType, indicator_file.stem, enum_value)
        modules[module_name] = enum_value
    indicator.TYPE_MAPPING = {
        "indicator": indicator.Indicator,
        "indicators": indicator.Indicator,
    }
    for module_name, enum_value in modules.items():
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, indicator.Indicator):
                indicator.TYPE_MAPPING[enum_value] = obj
                setattr(indicator, obj.__name__, obj)
    for key in indicator.TYPE_MAPPING:
        if key in ["indicator", "indicators"]:
            continue
        cls = indicator.TYPE_MAPPING[key]
        if not indicator.IndicatorTypes:
            indicator.IndicatorTypes = cls
        else:
            indicator.IndicatorTypes |= cls


def load_observables():
    logger.info("Registering observables")
    modules = dict()
    for observable_file in Path(__file__).parent.glob("observables/**/*.py"):
        if observable_file.stem == "__init__":
            continue
        logger.info(f"Registering observable type {observable_file.stem}")
        if observable_file.parent.stem == "observables":
            module_name = f"core.schemas.observables.{observable_file.stem}"
        elif observable_file.parent.stem == "private":
            module_name = f"core.schemas.observables.private.{observable_file.stem}"
        if observable_file.stem not in observable.ObservableType.__members__:
            aenum.extend_enum(
                observable.ObservableType, observable_file.stem, observable_file.stem
            )
        modules[module_name] = observable_file.stem
    if "guess" not in observable.ObservableType.__members__:
        aenum.extend_enum(observable.ObservableType, "guess", "guess")
    observable.TYPE_MAPPING = {
        "observable": observable.Observable,
        "observables": observable.Observable,
    }
    for module_name, enum_value in modules.items():
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, observable.Observable):
                observable.TYPE_MAPPING[enum_value] = obj
                setattr(observable, obj.__name__, obj)
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
