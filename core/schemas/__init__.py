import importlib
import inspect
import logging
from pathlib import Path

import aenum

from core.schemas import observable

logger = logging.getLogger(__name__)

logger.info("Registering observable types")


def load_observables():
    for observable_file in Path(__file__).parent.glob("observables/**/*.py"):
        if observable_file.stem == "__init__":
            continue
        logger.info(f"Registering observable type {observable_file.stem}")
        if observable_file.parent.stem == "observables":
            module_name = f"core.schemas.observables.{observable_file.stem}"
        elif observable_file.parent.stem == "private":
            module_name = f"core.schemas.observables.private.{observable_file.stem}"
        aenum.extend_enum(
            observable.ObservableType, observable_file.stem, observable_file.stem
        )
        module = importlib.import_module(module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, observable.Observable):
                observable.TYPE_MAPPING[observable_file.stem] = obj
    aenum.extend_enum(observable.ObservableType, "guess", "guess")


load_observables()
