"""Guards the static type registries in observable.py / entity.py / indicator.py.

Public schema types are registered by hand (explicit imports + TYPE_MAPPING +
the *Types union). This test globs each family package and fails if a subtype
is defined on disk but not wired into its registry — preserving the old
"drop a file in and it works" ergonomics as "drop a file in and CI tells you
to register it".
"""

import importlib
import inspect
import pathlib
import typing
import unittest

from core.schemas import entity, indicator, observable


class RegistryCompletenessTest(unittest.TestCase):
    def _check(self, base_module, base_class, package: str):
        pkg_path = pathlib.Path(base_module.__file__).parent / package
        union = getattr(base_module, f"{base_class.__name__}Types")
        union_args = set(typing.get_args(union))
        type_mapping = base_module.TYPE_MAPPING

        found_any = False
        for pyfile in sorted(pkg_path.glob("*.py")):
            if pyfile.stem == "__init__":
                continue
            module = importlib.import_module(f"core.schemas.{package}.{pyfile.stem}")
            for _, cls in inspect.getmembers(module, inspect.isclass):
                if cls.__module__ != module.__name__:
                    continue
                if not issubclass(cls, base_class) or cls is base_class:
                    continue
                if "type" not in cls.model_fields:
                    continue
                found_any = True
                type_value = cls.model_fields["type"].default
                with self.subTest(cls=cls.__name__):
                    self.assertIn(
                        type_value,
                        type_mapping,
                        f"{cls.__name__} ({type_value!r}) is missing from "
                        f"{package} TYPE_MAPPING — register it in {base_module.__name__}",
                    )
                    self.assertIs(type_mapping[type_value], cls)
                    self.assertIn(
                        cls,
                        union_args,
                        f"{cls.__name__} is missing from {base_class.__name__}Types "
                        f"— add it to the union in {base_module.__name__}",
                    )
        self.assertTrue(found_any, f"No subtypes discovered in {package}")

    def test_observables_registered(self):
        self._check(observable, observable.Observable, "observables")

    def test_entities_registered(self):
        self._check(entity, entity.Entity, "entities")

    def test_indicators_registered(self):
        self._check(indicator, indicator.Indicator, "indicators")


if __name__ == "__main__":
    unittest.main()
