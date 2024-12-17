from typing import ClassVar, Literal

import yara
from pydantic import BaseModel, PrivateAttr, field_validator

from core.schemas import indicator


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
    type: Literal["yara"] = "yara"

    @field_validator("pattern")
    @classmethod
    def validate_yara(cls, value) -> str:
        try:
            yara.compile(source=value)
        except yara.SyntaxError as error:
            raise ValueError(f"Invalid Yara rule: {error}")
        return value

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = yara.compile(source=self.pattern)
        return self._compiled_pattern

    def match(self, value: str | bytes) -> YaraMatch | None:
        result = self.compiled_pattern.match(data=value)
        yaramatch = native_yara_to_yara_match(result)
        if result:
            return YaraMatch(matches=yaramatch.matches)
        return None
