from typing import ClassVar, Literal

from core.schemas import indicator


class Yara(indicator.Indicator):
    """Represents a Yara rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = "yara"
    type: Literal["yara"] = "yara"

    def match(self, value: str) -> indicator.IndicatorMatch | None:
        raise NotImplementedError
