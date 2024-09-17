import importlib
import inspect
import logging
from pathlib import Path

import aenum

from core.schemas import entity, observable

logger = logging.getLogger(__name__)

def load_observables():
    logger.info("Registering observable types")
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
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, observable.Observable):
                observable.TYPE_MAPPING[observable_file.stem] = obj
    if "guess" not in observable.ObservableType.__members__:
        aenum.extend_enum(observable.ObservableType, "guess", "guess")


def load_entities():
    logger.info("Registering entity types")
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
            aenum.extend_enum(
                entity.EntityType, entity_file.stem, enum_value
            )
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, entity.Entity):
                entity.TYPE_MAPPING[enum_value] = obj
    for key in entity.TYPE_MAPPING:
        if key in ["entity", "entities"]:
            continue
        cls = entity.TYPE_MAPPING[key]
        if not entity.EntityTypes:
            entity.EntityTypes = cls
        else:
            entity.EntityTypes |= cls


load_observables()
load_entities()
