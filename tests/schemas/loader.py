"""Guards core.schemas.loader: private type discovery, and the checks that keep
every type's `type` field usable as a pydantic discriminator.

The API's request and response models discriminate the observable, entity and
indicator unions on `type`, so every member, private types included, has to
declare `type` as a single-value Literal that no other member uses. A private
type that breaks that rule must not take the whole API down with a pydantic
schema-generation traceback.
"""

import importlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from typing import Literal

from core.schemas import loader
from core.schemas.observable import Observable
from core.schemas.observables.ipv4 import IPv4
from core.schemas.observables.url import Url

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

GOOD_PRIVATE = """
    from typing import Literal

    from core.schemas.observable import Observable


    class GoodPrivate(Observable):
        type: Literal["good_private"] = "good_private"
"""

STR_TYPED_PRIVATE = """
    from core.schemas.observable import Observable


    class StrTyped(Observable):
        type: str = "str_typed"
"""

DUPLICATE_IPV4_PRIVATE = """
    from typing import Literal

    from core.schemas.observable import Observable


    class DuplicateIPv4(Observable):
        type: Literal["ipv4"] = "ipv4"
"""


class PrivatePackageMixin(unittest.TestCase):
    def make_private_dir(self, modules: dict[str, str]) -> pathlib.Path:
        """Writes `modules` (name -> source) into a fresh `private` directory."""
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        private = root / "private"
        private.mkdir()
        (private / "__init__.py").write_text("")
        for module_name, source in modules.items():
            (private / f"{module_name}.py").write_text(textwrap.dedent(source))
        return private

    def make_private_package(self, name: str, modules: dict[str, str]) -> None:
        """Makes `<name>.private.<module>` importable, like a deployment's
        `core.schemas.observables.private` package."""
        private = self.make_private_dir(modules)
        root = private.parent
        package = root / name
        package.mkdir()
        (package / "__init__.py").write_text("")
        private.rename(package / "private")
        sys.path.insert(0, str(root))
        self.addCleanup(sys.path.remove, str(root))
        self.addCleanup(self._forget_modules, name)
        importlib.invalidate_caches()

    @staticmethod
    def _forget_modules(name: str) -> None:
        for key in [k for k in sys.modules if k == name or k.startswith(f"{name}.")]:
            del sys.modules[key]


class LoadPrivateTypesTest(PrivatePackageMixin):
    def test_skips_private_type_whose_type_is_not_a_literal(self):
        self.make_private_package(
            "loadertest_mixed", {"good": GOOD_PRIVATE, "bad": STR_TYPED_PRIVATE}
        )

        with self.assertLogs("core.schemas.loader", level="ERROR") as logs:
            classes = loader.load_private_types("loadertest_mixed", Observable)

        self.assertEqual([cls.__name__ for cls in classes], ["GoodPrivate"])
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        self.assertIn("StrTyped", message)
        self.assertIn("loadertest_mixed.private.bad", message)
        self.assertIn("Literal", message)


class CheckDiscriminatorFieldsTest(unittest.TestCase):
    def test_accepts_types_with_distinct_literal_values(self):
        loader.check_discriminator_fields([IPv4, Url], "observable")

    def test_rejects_duplicate_type_values(self):
        class DuplicateIPv4(Observable):
            type: Literal["ipv4"] = "ipv4"

        with self.assertRaisesRegex(TypeError, r"IPv4.*DuplicateIPv4.*'ipv4'"):
            loader.check_discriminator_fields([IPv4, DuplicateIPv4], "observable")

    def test_rejects_type_that_is_not_a_literal(self):
        class StrTyped(Observable):
            type: str = "str_typed"

        with self.assertRaisesRegex(TypeError, r"StrTyped.*Literal"):
            loader.check_discriminator_fields([IPv4, StrTyped], "observable")


class ApiStartupTest(PrivatePackageMixin):
    """Imports the API in a subprocess with a private observable in place.

    The private package object is seeded in sys.modules with its __path__ set
    to a temporary directory, so the real loader discovers the test's module
    under its real name without writing into core/schemas/observables/private.
    """

    def import_api_with_private(self, modules: dict[str, str]):
        private = self.make_private_dir(modules)
        code = textwrap.dedent(f"""
            import sys
            import types

            package = types.ModuleType("core.schemas.observables.private")
            package.__path__ = [{str(private)!r}]
            sys.modules[package.__name__] = package

            import core.web.webapp  # noqa: F401
            from core.schemas import observable

            print("TYPE_MAPPING:", " ".join(sorted(observable.TYPE_MAPPING)))
        """)
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO_ROOT,
            env=os.environ,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_api_starts_without_a_str_typed_private_type(self):
        result = self.import_api_with_private({"bad": STR_TYPED_PRIVATE})

        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertNotIn("str_typed", result.stdout)
        self.assertIn("ipv4", result.stdout)

    def test_api_refuses_to_start_naming_a_duplicate_type_value(self):
        result = self.import_api_with_private({"dup": DUPLICATE_IPV4_PRIVATE})

        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr, r"TypeError: .*IPv4.*DuplicateIPv4.*'ipv4'")


if __name__ == "__main__":
    unittest.main()
