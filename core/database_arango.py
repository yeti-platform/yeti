"""Class implementing a YetiConnector interface for ArangoDB."""
import json
import sys
import time
from typing import TypeVar, Iterable, Type, Any, List

import requests
from arango import ArangoClient
from arango.exceptions import (DocumentInsertError, DocumentUpdateError,
                               GraphCreateError)
from dateutil import parser

from core.config.config import yeti_config

from .interfaces import AbstractYetiConnector

LINK_TYPE_TO_GRAPH = {
    'tagged': 'tags',
    'stix': 'stix',
}

TYetiObject = TypeVar("TYetiObject", bound="ArangoYetiConnector")


class ArangoDatabase:
    """Class that contains the base class for the database.

    Essentially a proxy that will delay the connection to the first call.
    """

    def __init__(self):
        self.db = None
        self.collections = dict()
        self.graphs = dict()

    def connect(self,
                host: str = None,
                port: int = None,
                username: str = None,
                password: str = None,
                database: str = None):

        host = host or yeti_config.arangodb.host
        port = port or yeti_config.arangodb.port
        username = username or yeti_config.arangodb.username
        password = password or yeti_config.arangodb.password
        database = database or yeti_config.arangodb.database

        host_string = f'http://{host}:{port}'
        client = ArangoClient(hosts=host_string)

        sys_db = client.db('_system', username=username, password=password)
        for _ in range(0, 4):
            try:
                yeti_db = sys_db.has_database(database)
                break
            except requests.exceptions.ConnectionError as e:
                print('Connection error: {0:s}'.format(str(e)))
                print('Retrying in 5 seconds...')
                time.sleep(5)
        else:
            print("Could not connect, bailing.")
            sys.exit(1)

        if not yeti_db:
            sys_db.create_database(database)

        self.db = client.db(database, username=username, password=password)

        self.create_edge_definition(self.graph('tags'), {
            'edge_collection': 'tagged',
            'from_vertex_collections': ['observables'],
            'to_vertex_collections': ['tags'],
        })
        self.create_edge_definition(self.graph('observables'), {
            'edge_collection': 'links',
            'from_vertex_collections': ['observables'],
            'to_vertex_collections': ['observables'],
        })

    def clear(self):
        for name in self.collections:
            self.collections[name].truncate()

    def collection(self, name):
        if self.db is None:
            self.connect()

        if name not in self.collections:
            if self.db.has_collection(name):
                self.collections[name] = self.db.collection(name)
            else:
                self.collections[name] = self.db.create_collection(name)

        return self.collections[name]

    def graph(self, name):
        if self.db is None:
            self.connect()

        try:
            return self.db.create_graph(name)
        except GraphCreateError as err:
            if err.error_code in [1207, 1925]:
                return self.db.graph(name)
            raise

    def create_edge_definition(self, graph, definition):
        if self.db is None:
            self.connect()

        if graph.has_edge_definition(definition['edge_collection']):
            collection = graph.edge_collection(definition['edge_collection'])
        else:
            collection = graph.create_edge_definition(**definition)
        self.collections[definition['edge_collection']] = collection
        return collection

    def __getattr__(self, key):
        if self.db is None and not key.startswith('__'):
            self.connect()
        return getattr(self.db, key)

db = ArangoDatabase()


class ArangoYetiConnector(AbstractYetiConnector):
    """Yeti connector for an ArangoDB backend."""
    _db = db

    def __init__(self):
        self._arango_id = None

    def _insert(self, document_json):
        try:
            newdoc = self._get_collection().insert(
                document_json, return_new=True)['new']
            newdoc['id'] = newdoc.pop('_key')
            return newdoc
        except DocumentInsertError as err:
            if not err.error_code == 1210: # Unique constraint violation
                raise
            conflict = 'name' if 'name' in document_json else 'value'
            error = 'A {0} object with same `{1}` already exists'.format(
                self.__class__.__name__, conflict)
            raise IntegrityError(str(error))

    def _update(self, document_json):
        document = json.loads(document_json)
        document['_key'] = document.pop('id')
        newdoc = self._get_collection().update(
            document, merge=False, return_new=True)['new']
        newdoc['id'] = newdoc.pop('_key')
        return newdoc

    def save(self: TYetiObject) -> TYetiObject:
        """Inserts or updates a Yeti object into the database.

        Returns:
          The created Yeti object."""
        doc_dict = self.dict(exclude_unset=True)
        if doc_dict.get('id') is not None:
            result = self._update(self.json())
        else:
            result = self._insert(self.json())
        return self.__class__(**result)

    def update_links(self, new_id):
        if not self._arango_id:
            return
        graph = self._db.graph('stix')
        neighbors = graph.traverse(
            self._arango_id, direction='any', max_depth=1)
        for path in neighbors['paths']:
            for edge in path['edges']:
                if edge['attributes']['target_ref'] == self.id:
                    edge['_to'] = new_id
                elif edge['attributes']['source_ref'] == self.id:
                    edge['_from'] = new_id
                graph.update_edge(edge)

    @classmethod
    def list(cls: Type[TYetiObject]) -> Iterable[TYetiObject]:
        """Lists all objects.

        Returns:
          A list of YetiObjects.
        """
        coll = cls._collection_name
        type_filter = cls._type_filter

        if type_filter:
            objects = cls._db.aql.execute(
                'FOR o IN @@collection FILTER o.type IN @type RETURN o',
                bind_vars={'type': type_filter, '@collection': coll})
        else:
            objects = cls._db.aql.execute(
                'FOR o IN @@collection RETURN o',
                bind_vars={'@collection': coll})

        for object in list(objects):
            object['id'] = object.pop('_key')
            yield cls.load(object)

    @classmethod
    def get(cls: Type[TYetiObject], id: str) -> TYetiObject | None:
        """Fetches a single object by key.

        Args:
          id: ArangoDB _key value

        Returns:
          A Yeti object."""
        document = cls._get_collection().get(id)
        if not document:
            return None
        document['id'] = document.pop('_key')
        return cls.load(document)

    @classmethod
    def find(cls: Type[TYetiObject], **kwargs) -> TYetiObject | None:
        """Fetches a single object by value.

        Args:
          value: The value to search for.

        Returns:
          A Yeti object.
        """
        documents = list(cls._get_collection().find(kwargs))
        if not documents:
            return None
        document = documents[0]
        document['id'] = document.pop('_key')
        return cls.load(document)

    @classmethod
    def get_or_create(cls, **kwargs):
        """Fetches an object matching dict_ or creates it.

        If an object matching kwargs is found, return the existing object. If
        not, create it and return the newly created object.

        Args:
          **kwargs: Dictionary used to create the object.

        Returns:
          A Yeti object.
        """
        obj = cls(**kwargs)
        try:
            return obj.save()
        except IntegrityError:
            return cls.find(**kwargs)

    def link_to(self, target, relationship_type=None):
        """Creates a link between two YetiObjects.

        Args:
          target: The YetiObject to link to.
          relationship_type: The type of link. (e.g. targets, uses, mitigates)
        """
        # from yeti.core.relationships import Relationship
        graph = self._db.graph('observables')
        source = f'{self._collection_name}/{self.id}'
        destination = f'{target._collection_name}/{target.id}'
        graph.edge_collection('links').link(source, destination)
        # existing = list(Relationship.filter({'attributes.id': stix_rel['id']}))
        # if existing:
        #     return existing[0]
        # # pylint: disable=protected-access
        # return Relationship(self._arango_id, target._arango_id, stix_rel).save()

    # pylint: disable=too-many-arguments
    def neighbors(self, link_type=None, direction='any', include_original=False,
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
        query_filter = ''
        if link_type:
            query_filter = f'FILTER e.attributes.relationship_type == "{link_type}"'
        aql = f"""
        FOR v, e, p IN 1..{hops} {direction} '{self._arango_id}'
          GRAPH 'stix'
          {query_filter}
          RETURN p
        """
        neighbors = list(self._db.aql.execute(aql))
        edges = []
        vertices = {}
        for path in neighbors:
            edges.extend(self._build_edges(path['edges']))
            self._build_vertices(vertices, path['vertices'])
        if not include_original:
            vertices.pop(self.id, None)
        edges = self._dedup_edges(edges)

        if not raw:
            vertices = {n.id: n for n in self.load(list(vertices.values()))}

        return {'edges': edges, 'vertices': vertices}

    def _dedup_edges(self, edges):
        """Deduplicates edges with same STIX ID, keeping the most recent one.

        Args:
          edges: list of JSON-serialized STIX2 SROs.

        Returns:
          A list of the most recent versions of JSON-serialized STIX2 SROs.
        """
        seen = {}
        for edge in edges:
            edge_id = edge['id']
            if edge_id in seen:
                seen_modified = parser.parse(seen[edge_id]['modified'])
                current_modified = parser.parse(edge['modified'])
                if seen_modified > current_modified:
                    continue
            seen[edge_id] = edge
        return list(seen.values())

    def _build_edges(self, arango_edges):
        return [edge['attributes'] for edge in arango_edges]

    def _build_vertices(self, vertices, arango_vertices):
        for vertex in arango_vertices:
            if vertex['stix_id'] not in vertices:
                vertices[vertex['stix_id']] = vertex

    @classmethod
    def filter(cls: Type[TYetiObject],
               args: dict[str, Any],
               offset: int,
               count: int) -> List[TYetiObject]:
        """Search in an ArangoDb collection.

        Search the collection for all objects whose 'value' attribute matches
        the regex defined in the 'value' key of the args dict.

        Args:
            args: A key:value dictionary containing a 'value' or 'name' key
              defining the regular expression to match against.
            offset: Skip this many objects when querying the DB.
            count: How many objecst after `offset` to return.

        Returns:
            A List of Yeti objects
        """
        cls._get_collection()
        colname = cls._collection_name
        conditions = []
        sorts = []
        for key in args:
            if key in ['value', 'name', 'type', 'stix_id', 'attributes.id', 'email']:
                conditions.append('o.{0:s} =~ @{1:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))
            if key in ['labels']:
                conditions.append('@{1:s} ALL IN o.{0:s}'.format(key, key.replace('.', '_')))
                sorts.append('o.{0:s}'.format(key))

        limit = ''
        if offset and count:
            limit = f'LIMIT {offset}, {count}'

        aql_string = f"""
            FOR o IN @@collection
                FILTER {' AND '.join(conditions)}
                SORT {', '.join(sorts)}
                {limit}
                RETURN o
            """

        args['@collection'] = colname
        for key in list(args.keys()):
            args[key.replace('.', '_')] = args.pop(key)
        documents = cls._db.aql.execute(aql_string, bind_vars=args)
        results = []
        for doc in documents:
            doc['id'] = doc.pop('_key')
            results.append(cls.load(doc))
        return results

    @classmethod
    def fulltext_filter(cls, keywords):
        """Search in an ArangoDB collection using full-text search.

        Args:
          query: Keywords to use in the full-text query.

        Returns:
          A List of Yeti objects.
        """
        collection = cls._get_collection()
        query = ','.join(keywords)
        yeti_objects = []
        key = cls._text_indexes[0]['fields'][0]
        for document in collection.find_by_text(key, query):
            document['id'] = document.pop('_key')
            yeti_objects.append(cls.load(document, strict=True))
        return yeti_objects

    def delete(self, all_versions=True):
        """Deletes an object from the database."""
        if self._db.graph('stix').has_vertex_collection(self._collection_name):
            col = self._db.graph('stix').vertex_collection(self._collection_name)
        else:
            col = self._db.collection(self._collection_name)
        col.delete(self._arango_id)
        if all_versions:
            for version in self.all_versions():
                version.delete(all_versions=False)

    @classmethod
    def _get_collection(cls):
        """Get the collection corresponding to this Yeti object class.

        Ensures the collection is properly indexed.

        Returns:
          The ArangoDB collection corresponding to the object class.
        """
        collection = cls._db.collection(cls._collection_name)
        # for index in cls._indexes:
        #     collection.add_hash_index(**index)
        # for text_index in cls._text_indexes:
        #     collection.add_fulltext_index(**text_index)
        return collection
