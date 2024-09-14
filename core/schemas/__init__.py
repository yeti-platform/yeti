import importlib
import inspect
from pathlib import Path

import aenum

from core.schemas import observable

print("Registering observable types")

for observable_file in Path(__file__).parent.glob("observables/**/*.py"):
    if observable_file.stem == "__init__":
        continue
    print(f"Registering observable type {observable_file.stem}")
    if observable_file.parent.stem == "observables":
        module_name = f"core.schemas.observables.{observable_file.stem}"
    elif observable_file.parent.stem == "private":
        module_name = f"core.schemas.observables.private.{observable_file.stem}"
    aenum.extend_enum(observable.ObservableType, observable_file.stem, observable_file.stem)
    module = importlib.import_module(module_name)
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, observable.Observable):
            observable.TYPE_MAPPING[observable_file.stem] = obj