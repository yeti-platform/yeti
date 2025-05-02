import re
from typing import ClassVar, Literal

from pydantic import BaseModel, PrivateAttr, field_validator

from core.schemas import indicator


class RegexMatch(BaseModel):
    name: str
    matched_string: str


class Regex(indicator.Indicator):
    _type_filter: ClassVar[str] = "regex"
    _compiled_pattern: re.Pattern | None = PrivateAttr(None)
    type: Literal["regex"] = "regex"

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
        except OverflowError:
            raise ValueError("Regex pattern is too large")
        return value

    def match(self, value: str) -> RegexMatch | None:
        result = self.compiled_pattern.search(value)
        if result:
            return RegexMatch(name=self.name, matched_string=result.group())
        return None
