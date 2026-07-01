#!/usr/bin/env python3
"""Validates that a DFIQ archive's yaml files are internally consistent.

Every object's uuid must be well-formed, and every parent_ids entry must
resolve to another object's uuid or dfiq_id present in the same archive.
DFIQ import calls update_parents(soft_fail=True), so a mismatch here would
otherwise silently produce an unlinked scenario/facet/question hierarchy
instead of a loud failure.

The archive must also only contain yaml files (directory entries aside) -
no scripts, executables, or any other file type. This is checked both by
extension and by sniffing the actual file content with Magika, so a
disguised executable renamed to *.yaml is also rejected.

Usage:
    python tools/validate_dfiq_archive.py tests/dfiq_test_data/dfiq_test_data.zip
"""

import argparse
import sys
import uuid
from zipfile import ZipFile

import yaml
from magika import Magika

_MAGIKA = Magika()


def validate(archive_path: str) -> list[str]:
    """Checks a DFIQ archive for uuid and parent_ids consistency.

    Args:
        archive_path: path to the DFIQ zip archive to validate.

    Returns:
        A list of human-readable error messages. Empty if the archive is
        consistent.
    """
    errors = []
    yaml_by_uuid = {}

    with ZipFile(archive_path) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue  # directory entry
            if not name.endswith(".yaml"):
                errors.append(f"{name} is not a .yaml file")
                continue

            with archive.open(name) as f:
                content = f.read()

            content_type = _MAGIKA.identify_bytes(content).output.label
            if content_type not in ("yaml", "empty"):
                errors.append(
                    f"{name} has a .yaml extension but its content was "
                    f"detected as {content_type!r}"
                )
                continue

            yaml_data = yaml.safe_load(content)

            if yaml_data.get("uuid") is None:
                errors.append(f"{name} is missing a uuid")
                continue
            try:
                uuid.UUID(str(yaml_data["uuid"]))
            except ValueError:
                errors.append(f"{name} has an invalid uuid: {yaml_data['uuid']!r}")
                continue
            yaml_by_uuid[yaml_data["uuid"]] = (name, yaml_data)

    dfiq_ids = {data["id"] for _, data in yaml_by_uuid.values()}
    for name, yaml_data in yaml_by_uuid.values():
        for parent_id in yaml_data.get("parent_ids") or []:
            if parent_id in yaml_by_uuid or parent_id in dfiq_ids:
                continue
            errors.append(
                f"{name}: parent_id {parent_id!r} referenced by "
                f"{yaml_data['id']} is not present in the archive"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="path to the DFIQ zip archive to validate")
    args = parser.parse_args()

    errors = validate(args.archive)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"{args.archive}: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
