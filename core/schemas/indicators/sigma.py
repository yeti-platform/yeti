from typing import ClassVar, Literal

from core.schemas import indicator


class Sigma(indicator.Indicator):
    """Represents a Sigma rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = "sigma"
    type: Literal["sigma"] = "sigma"
