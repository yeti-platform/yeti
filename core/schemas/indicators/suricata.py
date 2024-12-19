import logging
from typing import ClassVar, List, Literal

from idstools import rule
from pydantic import field_validator

from core.schemas import indicator


class Suricata(indicator.Indicator):
    """Represents a Suricata rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = "suricata"
    type: Literal["suricata"] = "suricata"
    sid: int = 0
    metadata: List[str] = []
    references: List[str] = []

    @field_validator("pattern")
    @classmethod
    def validate_rules(cls, value) -> str:
        try:
            rule.parse(value)
        except Exception as e:
            raise ValueError(f"invalid {cls.pattern} {e}")
        return value

    def parse(self) -> rule.Rule | None:
        try:
            return rule.parse(self.pattern)
        except Exception as e:
            logging.error(f" Error parsing {self.pattern} {e}")
