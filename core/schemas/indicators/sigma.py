from typing import ClassVar, Literal

from core.schemas import indicator


class Sigma(indicator.Indicator):
    """Represents a Sigma rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = indicator.IndicatorType.sigma
    type: Literal[indicator.IndicatorType.sigma] = indicator.IndicatorType.sigma

    def match(self, value: str) -> indicator.IndicatorMatch | None:
        raise NotImplementedError
