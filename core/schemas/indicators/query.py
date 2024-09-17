from typing import ClassVar, Literal

from core.schemas import indicator


class Query(indicator.Indicator):
    """Represents a query that can be sent to another system."""

    _type_filter: ClassVar[str] = indicator.IndicatorType.query
    type: Literal[indicator.IndicatorType.query] = indicator.IndicatorType.query

    query_type: str
    target_systems: list[str] = []

    def match(self, value: str) -> indicator.IndicatorMatch | None:
        return None
