"""YetiConnector interface.

This interface defines the methods a YetiConnector needs to implement to
successfully carry out all interactions with the database.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, List, Type, TypeVar

if TYPE_CHECKING:
    from core.schemas import entity, indicator, observable, tag
    from core.schemas.graph import GraphFilter, Relationship, TagRelationship

TYetiObject = TypeVar("TYetiObject")


class AbstractYetiConnector(ABC):
    @classmethod
    @abstractmethod
    def load(cls, object):
        """Load a YetiObject from a database object."""
        raise NotImplementedError

    @abstractmethod
    def save(self):
        """Inserts or updates a Yeti object into the database.

        Returns:
          The created Yeti object."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def list(cls):
        """Lists all objects.

        Returns:
          A list of objects contained in the database."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def get(cls, key):
        """Fetches a single object by primary key.

        Args:
          key: A database primary key value.

        Returns:
          A Yeti object."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def filter(
        cls: Type[TYetiObject],
        query_args: dict[str, Any],
        tag_filter: List[str] = [],
        offset: int = 0,
        count: int = 0,
        sorting: List[tuple[str, bool]] = [],
        aliases: List[tuple[str, str]] = [],
        graph_queries: List[tuple[str, str, str, str]] = [],
    ) -> tuple[List[TYetiObject], int]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            query_args: A key:value dictionary containing keys to filter objects
                on.
            tag_filter: A list of tags to filter on.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.
            sorting: A list of (order, ascending) fields to sort by.
            graph_queries: A list of (name, graph, direction, field) tuples to
                query the graph with.

        Returns:
            A List of Yeti objects, and the total object count.
        """
        raise NotImplementedError

    @abstractmethod
    def link_to(
        self, target, relationship_type: str, description: str
    ) -> "Relationship":
        """Creates a link from an existing object to a target object.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
          stix_rel: JSON-serialized STIX Relationship object
        """
        raise NotImplementedError

    @abstractmethod
    # pylint: disable=too-many-arguments
    def neighbors(
        self,
        link_types: List[str] = [],
        target_types: List[str] = [],
        direction: str = "any",
        graph: str = "links",
        filter: List["GraphFilter"] = [],
        include_original: bool = False,
        min_hops: int = 1,
        max_hops: int = 1,
        offset: int = 0,
        count: int = 0,
    ) -> tuple[
        dict[
            str, "observable.Observable | entity.Entity | indicator.Indicator | tag.Tag"
        ],
        List[List["Relationship | TagRelationship"]],
        int,
    ]:
        """Fetches neighbors of the YetiObject.

        Args:
          link_type: The type of link.
          direction: outbound, inbound, or any.
          include_original: Whether the original object is to be included in the
              result or not.
          hops: The maximum number of nodes to go through (defaults to 1:
              direct neighbors)
          raw: Whether to return a raw dictionary or a Yeti object.
        """
        raise NotImplementedError

    def update(self, args):
        """Updates an object with a dictionary.

        Args:
          args: key:value dictionary used to update the object.
        """
        for key, value in args.items():
            setattr(self, key, value)
        return self
