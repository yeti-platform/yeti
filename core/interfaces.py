"""YetiConnector interface.

This interface defines the methods a YetiConnector needs to implement to
successfully carry out all interactions with the database.
"""

from abc import abstractmethod, ABC

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
    def get_or_create(cls, **kwargs):
        """Fetches an object matching dict_ or creates it.

        Args:
          **kwargs: Key-value dictionary used to create the object.

        Returns:
          A Yeti object.
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def filter(cls, args, offset=None, count=None):
        """Filters objects according to args.

        Args:
          args: parameters used to filter the objects.
          offset: Skip this many objects when querying the DB.
          count: How many objecst after `offset` to return.
        """
        raise NotImplementedError

    @abstractmethod
    def link_to(self, target, relationship_type=None, stix_rel=None):
        """Creates a link from an existing object to a target object.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
          stix_rel: JSON-serialized STIX Relationship object
        """
        raise NotImplementedError

    @abstractmethod
    # pylint: disable=too-many-arguments
    def neighbors(self, link_type, direction='any', include_original=False,
                  hops=1, raw=False):
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
