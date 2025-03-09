import logging
from typing import ClassVar, Literal

import plyara
import plyara.exceptions
import plyara.utils
import yara
from pydantic import BaseModel, PrivateAttr, model_validator

from core import errors
from core.schemas import indicator

ALLOWED_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
    "vt": "",
}


logger = logging.getLogger(__name__)


class MatchInstance(BaseModel):
    """
    Represents an instance of a string match.

    Attributes:
        offset: The offset where the string matched in the scanned data.
        matched_data: The actual bytes that matched.
    """

    offset: int
    matched_data: bytes


class StringMatch(BaseModel):
    """
    Represents a Yara string match.

    Attributes:
        identifier: The identifier of the matching string.
        instances: A list of MatchInstance objects representing the instances where the string matched.
    """

    identifier: str
    instances: list[MatchInstance]


class RuleMatch(BaseModel):
    """
    Represents a Yara rule match.

    Attributes:
        rule: The name of the matching rule.
        namespace: The namespace of the matching rule.
        tags: A list of tags associated with the rule.
        meta: A dictionary of metadata associated with the rule.
        strings: A list of StringMatch objects representing the matching strings.
    """

    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[StringMatch]


class YaraMatch(BaseModel):
    """
    Represents the overall Yara scan result.

    Attributes:
        matches: A list of RuleMatch objects representing the matching rules.
    """

    matches: list[RuleMatch]


def native_yara_to_yara_match(match: yara.Match) -> YaraMatch:
    """
    Convert a native Yara match object to a YaraMatch object.

    Args:
        match: The native Yara match object to convert.

    Returns:
        A YaraMatch object representing the converted match.
    """
    matches = []
    for rule_match in match:
        strings = []
        for string_match in rule_match.strings:
            instances = []
            for instance in string_match.instances:
                instances.append(
                    MatchInstance(
                        offset=instance.offset, matched_data=instance.matched_data
                    )
                )
            strings.append(
                StringMatch(identifier=string_match.identifier, instances=instances)
            )
        matches.append(
            RuleMatch(
                rule=rule_match.rule,
                namespace=rule_match.namespace,
                tags=rule_match.tags,
                meta=rule_match.meta,
                strings=strings,
            )
        )
    return YaraMatch(matches=matches)


class Yara(indicator.Indicator):
    """Represents a Yara rule."""

    _type_filter: ClassVar[str] = "yara"
    _compiled_pattern: yara.Match | None = PrivateAttr(None)

    name: str = ""  # gets overridden during validation
    type: Literal["yara"] = "yara"
    dependencies: list[str] = []
    private: bool = False

    def validate_yara(self):
        rule = self.pattern
        if not rule:
            raise ValueError("Yara rule body is required.")
        try:
            rules = plyara.Plyara().parse_string(rule)
        except plyara.exceptions.ParseTypeError as error:
            raise ValueError(str(error)) from error
        if len(rules) > 1:
            raise ValueError("Only one Yara rule is allowed in the rule body.")
        if not rules:
            raise ValueError("No valid Yara rules found in the rule body.")
        parsed_rule = rules[0]
        rule_deps = set(plyara.utils.detect_dependencies(parsed_rule))
        self.dependencies = list(rule_deps - ALLOWED_EXTERNALS.keys())
        self.name = parsed_rule["rule_name"]
        self.private = "private" in parsed_rule.get("scopes", [])

    def save(self):
        try:
            self.validate_yara()
        except ValueError as error:
            raise errors.ObjectCreationError(str(error)) from error

        missing_deps = []
        for dep_name in self.dependencies:
            dep = Yara.find(name=dep_name)
            if not dep:
                missing_deps.append(dep_name)
        if missing_deps:
            raise errors.ObjectCreationError(
                "Missing dependency when creating Yara rule",
                meta={"missing_dependencies": missing_deps},
            )

        self = super().save()
        nodes, relationships, _ = self.neighbors(
            link_types=["depends"], direction="outbound", max_hops=1
        )

        for edge in relationships:
            for rel in edge:
                if nodes[rel.target].name not in self.dependencies:
                    rel.delete()

        for dependency in self.dependencies:
            dep = Yara.find(name=dependency)
            self.link_to(dep, "depends", "Depends on")

        return self

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = yara.compile(
                source=self.pattern, externals=ALLOWED_EXTERNALS
            )
        return self._compiled_pattern

    def match(self, value: str | bytes) -> YaraMatch | None:
        result = self.compiled_pattern.match(data=value)
        yaramatch = native_yara_to_yara_match(result)
        if result:
            return YaraMatch(matches=yaramatch.matches)
        return None

    @classmethod
    def import_bulk_rules(cls, bulk_rule_text: str, tags: list[str] | None = None):
        """Import bulk rules from a rule body.

        Args:
            bulk_rule_text: The text containing the bulk rules.
            tags: A list of tags to apply to the imported rules.
        """
        if not tags:
            tags = []

        try:
            yara.compile(source=bulk_rule_text, externals=ALLOWED_EXTERNALS)
        except yara.SyntaxError as error:
            raise ValueError(str(error)) from error

        parsed_rules = plyara.Plyara().parse_string(bulk_rule_text)
        # all_rule_names = {rule["rule_name"] for rule in parsed_rules}

        for rule in parsed_rules:
            raw_rule = plyara.utils.rebuild_yara_rule(rule)
            print(f"Processing {rule['rule_name']}")
            yara_object = Yara(
                name=rule["rule_name"],
                pattern=raw_rule,
                diamond=indicator.DiamondModel.capability,
                location=rule.get("scan_context", "N/A"),
            ).save()

            rule_tags = rule.get("tags", [])
            try:
                if rule_tags and isinstance(rule_tags, str):
                    rule_tags = rule_tags.split(",")
            except ValueError:
                rule_tags = []

            if tags + rule_tags:
                yara_object.tag(tags + rule_tags)

    def rule_with_dependencies(
        self, resolved: set[str] | None = None, seen: set[str] | None = None
    ) -> str:
        """
        Find dependencies in a Yara rule.

        Returns:
            A string containing the original rule text with dependencies added.
        """
        if resolved is None:
            resolved = set()
        if seen is None:
            seen = set()

        if self.name in seen:
            raise ValueError(f"Circular dependency detected: {self.name}")

        seen.add(self.name)

        concatenated_rules = ""

        dependencies = self.dependencies

        for dependency in dependencies:
            if dependency in resolved:
                continue
            logger.info(f"Resolving dependency: {dependency}")
            dep_rule = Yara.find(name=dependency)
            if not dep_rule:
                raise ValueError(f"Rule depends on unknown dependency '{dependency}'")
            concatenated_rules += dep_rule.rule_with_dependencies(resolved, seen)

        if self.name not in resolved:
            concatenated_rules += self.pattern + "\n\n"
            resolved.add(self.name)

        seen.remove(self.name)
        return concatenated_rules

    @classmethod
    def render_with_overlays(cls, pattern, rule_map, overlays):
        parsed_rules = plyara.Plyara().parse_string(pattern)
        final = ""
        for rule in parsed_rules:
            db_rule = rule_map.get(rule["rule_name"])
            if not db_rule:
                raise ValueError(f"Rule {rule['rule_name']} not found in database.")
            db_rule.apply_overlays_plyara(rule, overlays)
            final += db_rule.pattern
        return final

    def apply_overlays_plyara(
        self, overlays: set[str], parsed_rule: dict | None = None
    ):
        """Apply an overlay to a Yara rule.

        Args:
            overlay: The overlays to apply.
            parsed_rule: The parsed rule to apply the overlays to. If not provided
                the rule will be parsed from the pattern.
        """
        if not parsed_rule:
            parsed_rule = plyara.Plyara().parse_string(self.pattern)[0]

        metadata_overlay: dict[str, str | int] = {}
        parsed_rule_meta = parsed_rule.get("metadata", [])

        for context in self.context:
            if context["source"] in overlays:
                if metadata_overlay:
                    raise ValueError(f"Multiple overlays detected: {context['source']}")
                del context["source"]
                metadata_overlay.update(context)

        remaining = set(metadata_overlay.keys())
        for item in parsed_rule_meta:
            for key in metadata_overlay:
                if key in item:
                    item[key] = metadata_overlay[key]
                    remaining.remove(key)

        for key in remaining:
            parsed_rule_meta.append({key: metadata_overlay[key]})
        self.pattern = plyara.utils.rebuild_yara_rule(parsed_rule)

        return self

    @classmethod
    def generate_yara_bundle(cls, rules: list["Yara"]) -> str:
        """Export a list of Yara rules to a single string.

        Args:
            rules: A list of Yara rules to export.

        Returns:
            A string containing the exported rules.
        """
        resolved: set[str] = set()
        bulk_rules = ""
        for rule in rules:
            bulk_rules += rule.rule_with_dependencies(resolved)
        return bulk_rules
