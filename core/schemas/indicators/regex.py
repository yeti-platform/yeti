import re
from typing import ClassVar, Literal

from pydantic import PrivateAttr, field_validator

from core.schemas import indicator


class Regex(indicator.Indicator):
    _type_filter: ClassVar[str] = indicator.IndicatorType.regex
    _compiled_pattern: re.Pattern | None = PrivateAttr(None)
    type: Literal[indicator.IndicatorType.regex] = indicator.IndicatorType.regex

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, value) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f"Invalid regex pattern: {error}")
        return value

    def match(self, value: str) -> indicator.IndicatorMatch | None:
        result = self.compiled_pattern.search(value)
        if result:
            return indicator.IndicatorMatch(name=self.name, match=result.group())
        return None