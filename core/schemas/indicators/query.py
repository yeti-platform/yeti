import logging
from typing import ClassVar, Literal, Self

from core.schemas import indicator


class Query(indicator.Indicator):
    """Represents a query that can be sent to another system."""

    _type_filter: ClassVar[str] = "query"
    type: Literal["query"] = "query"

    query_type: str
    target_systems: list[str] = []

    @classmethod
    def for_query_type(cls, query_type: str) -> list[Self]:
        """Returns the queries meant for one system, such as "shodan".

        The match ignores case but is otherwise exact. query_type is free
        text, so near misses such as "shodan-c2" are logged: they would
        otherwise never run, and nothing would say why.
        """
        # "type" gives the view a search condition to narrow on; "~" matches
        # as a case-insensitive regex, anchored so it is exact.
        matching, _ = cls.filter({"type": "query", "query_type~": f"^{query_type}$"})
        similar, _ = cls.filter({"type": "query", "query_type~": query_type})
        matched_ids = {query.id for query in matching}
        near_misses = [query for query in similar if query.id not in matched_ids]
        if near_misses:
            logging.warning(
                "Not running query indicators whose query_type resembles "
                f"{query_type!r} but is not equal to it: "
                + ", ".join(f"{q.name!r} ({q.query_type})" for q in near_misses)
            )
        return matching
