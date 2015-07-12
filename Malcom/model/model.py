# from gevent import monkey; monkey.patch_socket()#subprocess()#socket(dns=False); monkey.patch_time();

import dateutil
import threading
import os
import pickle

import pymongo
from pymongo import MongoClient
from pymongo.son_manipulator import SONManipulator
from pymongo.read_preferences import ReadPreference
import pymongo.errors

from bson.objectid import ObjectId
from bson.json_util import dumps as bson_dumps
from bson.json_util import loads as bson_loads

from Malcom.auxiliary.toolbox import *
from Malcom.model.datatypes import Hostname, Url, Ip, As, Evil, DataTypes
from Malcom.model.user_management import UserManager


class Transform(SONManipulator):
    def transform_incoming(self, son, collection):
        for (key, value) in son.items():
            if isinstance(value, dict):
                son[key] = self.transform_incoming(value, collection)
        return son

    def transform_outgoing(self, son, collection):
        if 'type' in son:
            t = son['type']
            return DataTypes[t].from_dict(son)
        else:
            return son


class Model:
    def __init__(self, setup):
        read_pref = {'PRIMARY': ReadPreference.PRIMARY, 'PRIMARY_PREFERRED': ReadPreference.PRIMARY_PREFERRED,
                     'SECONDARY': ReadPreference.SECONDARY, 'SECONDARY_PREFERRED': ReadPreference.SECONDARY_PREFERRED,
                     'NEAREST': ReadPreference.NEAREST}
        db_setup = setup.get('DATABASE', {})
        self._connection = MongoClient(host=db_setup.get('HOSTS', ['localhost:27017']),
                                       replicaSet=db_setup.get('REPLSET', None),
                                       read_preference=read_pref[db_setup.get('READ_PREF', 'PRIMARY')])
        self._db = self._connection[db_setup.get('NAME', 'malcom')]
        if 'USERNAME' in db_setup:
            self._db.authenticate(db_setup['USERNAME'], password=db_setup.get('PASSWORD', None),
                                  source=db_setup.get('SOURCE', None))
        self._db.add_son_manipulator(Transform())

        # collections
        self.elements = self._db.elements
        self.graph = self._db.graph
        self.sniffer_sessions = self._db.sniffer_sessions
        self.feeds = self._db.feeds
        self.modules=self._db.modules
        self.history = self._db.history
        self.um = UserManager(setup)

        # create indexes
        self.rebuild_indexes()

        # locks
        self.db_lock = threading.Lock()

    def rebuild_indexes(self):
        # create indexes
        debug_output("Rebuilding indexes...")
        self.elements.ensure_index([('date_created', -1), ('value', 1)])
        self.elements.ensure_index([('date_first_seen', -1), ('value', 1)])
        self.elements.ensure_index([('date_last_seen', -1), ('value', 1)])
        self.elements.ensure_index('value', unique=True, dropDups=True)
        self.elements.ensure_index('tags')
        self.elements.ensure_index('next_analysis')
        self.elements.ensure_index('last_analysis')
        self.elements.ensure_index('bgp')
        self.graph.ensure_index([('src', 1), ('dst', 1)])
        self.graph.ensure_index('src')
        self.graph.ensure_index('dst')
        debug_output("Done rebuilding indexes...")

    def stats(self):
        stats = "DB loaded with %s elements\n" % self._db.elements.count()
        stats += "Graph has %s edges" % self._db.graph.count()
        return stats

    # =============== link operations =================

    def connect(self, src, dst, attribs="", commit=True):
        if not src or not dst:
            return None

        with self.db_lock:

            while True:
                try:
                    conn = self.graph.find_one({'src': ObjectId(src._id), 'dst': ObjectId(dst._id)})
                    break
                except Exception, e:
                    debug_output("Could not find connection from %s: %s" % (ObjectId(src._id), e), 'error')


            # if the connection already exists, just modify attributes and last seen time
            if conn:
                if attribs != "": conn['attribs'] = attribs
                conn['last_seen'] = datetime.datetime.utcnow()

            # if not, change the connection
            else:
                conn = {}
                conn['src'] = src._id
                conn['dst'] = dst._id
                conn['attribs'] = attribs
                conn['first_seen'] = datetime.datetime.utcnow()
                conn['last_seen'] = datetime.datetime.utcnow()
                debug_output("(linked %s to %s [%s])" % (str(src._id), str(dst._id), attribs), type='model')

            if commit:
                while True:
                    try:
                        self.graph.save(conn)
                        break
                    except Exception, e:
                        debug_output("Could not save %s: %s" % (conn, e), 'error')

        return conn

    def get_destinations(self, elt):
        return [e['value'] for e in self.graph.find({'src': elt['_id']}, 'value')]

    # =========== elements operations ============

    def find(self, query={}):
        return self.elements.find(query)

    def get(self, **kwargs):
        with self.db_lock:
            while True:
                try:
                    return self.elements.find_one(kwargs)
                except Exception, e:
                    debug_output(e, type='error')
                    pass

    def find_one(self, oid):
        return self.elements.find_one(oid)

    def find_neighbors(self, query, include_original=True):
        """Gets neighbors for all elements matching query"""

        # Get original elements
        elts = self.elements.find(query)

        # find neighbors for elements
        total_nodes, total_edges = self._multi_get_neighbors(elts, include_original=include_original)

        # Add display fields
        for e in total_nodes:
            e['fields'] = e.display_fields

        data = {'nodes': total_nodes, 'edges': total_edges}
        return data

    def _multi_get_neighbors(self, elts, query={}, include_original=True):
        """
        Function used by find_neighbors to get all unique neighbors for
        a given list of elements
        """

        original_ids = [e['_id'] for e in elts]

        new_edges = list(self.graph.find({'$or': [
            {'src': {'$in': original_ids}}, {'dst': {'$in': original_ids}}
        ]}))

        ids = set()
        for e in new_edges:
            ids.add(e['src'])
            ids.add(e['dst'])

        if include_original:
            ids = ids | set(original_ids)

        new_nodes = list(self.elements.find({'$and': [{'_id': {'$in': list(ids)}}, query]}))
        return new_nodes, new_edges

    def get_neighbors(self, elt, query={}, include_original=True):

        if not elt:
            return [], []

        d_new_edges = {}
        new_edges = []
        d_ids = {elt['_id']: elt['_id']}

        # get all links to / from the required element
        for e in self.graph.find({'src': elt['_id']}):
            d_new_edges[e['_id']] = e
            d_ids[e['dst']] = e['dst']
        for e in self.graph.find({'dst': elt['_id']}):
            d_new_edges[e['_id']] = e
            d_ids[e['src']] = e['src']


        # get all IDs of the new nodes that have been discovered
        ids = [d_ids[i] for i in d_ids]

        # get the new node objects
        nodes = {}
        for node in self.elements.find({'$and': [{"_id": {'$in': ids}}, query]}):
            nodes[node['_id']] = node

        # get incoming links (node weight)
        destinations = [d_new_edges[e]['dst'] for e in d_new_edges]
        for n in nodes:
            nodes[n]['incoming_links'] = destinations.count(nodes[n]['_id'])

        # get nodes IDs
        nodes_id = [nodes[n]['_id'] for n in nodes]
        # get links for new nodes, in case we use them
        for e in self.graph.find({'src': {'$in': nodes_id}}):
            d_new_edges[e['_id']] = e
        for e in self.graph.find({'dst': {'$in': nodes_id}}):
            d_new_edges[e['_id']] = e

        # create arrays
        new_edges = [d_new_edges[e] for e in d_new_edges]

        if not include_original:
            nodes = [nodes[n] for n in nodes if nodes[n]['value'] != elt['value']]
        else:
            nodes = [nodes[n] for n in nodes]

        # display
        for e in nodes:
            e['fields'] = e.display_fields

        return nodes, new_edges

    def single_graph_find(self, elt, query, depth=2):
        chosen_nodes = []
        chosen_links = []

        if depth > 0:
            # get a node's neighbors
            neighbors_n, neighbors_l = self.get_neighbors(elt, include_original=False)

            for i, node in enumerate(neighbors_n):
                # for each node, find evil (recursion)
                en, el = self.single_graph_find(node, query, depth=depth - 1)

                # if we found evil nodes, add them to the chosen_nodes list
                if len(en) > 0:
                    chosen_nodes += [n for n in en if n not in chosen_nodes] + [node]
                    chosen_links += [l for l in el if l not in chosen_links] + [neighbors_l[i]]

        n_query = {query['key']: {'$in': [query['value']]}}
        # if recursion ends, then search for evil neighbors

        neighbors_n, neighbors_l = self.get_neighbors(elt, n_query, include_original=False)

        # return evil neighbors if found
        if len(neighbors_n) > 0:
            chosen_nodes += [n for n in neighbors_n if n not in chosen_nodes]
            chosen_links += [l for l in neighbors_l if l not in chosen_links]

        return chosen_nodes, chosen_links

    def multi_graph_find(self, query, graph_query, depth=2):
        total_nodes = {}
        total_edges = {}

        for key in query:
            for value in query[key]:
                if key == '_id':
                    value = ObjectId(value)

                elt = self.elements.find_one({key: value})
                nodes, edges = self.single_graph_find(elt, graph_query, depth)
                for n in nodes:
                    total_nodes[n['_id']] = n
                for e in edges:
                    total_edges[e['_id']] = e

        total_nodes = [total_nodes[n] for n in total_nodes]
        total_edges = [total_edges[e] for e in total_edges]

        data = {'nodes': total_nodes, 'edges': total_edges}

        return data

    # ---- update & save operations ----

    def save(self, element, with_status=False):
        if None in [element['value'], element['type']]:
            raise ValueError("Invalid value for element: %s" % element)

        with self.db_lock:

            # critical section starts here
            tags = element.pop('tags', [])  # so tags in the db do not get overwritten
            evil = element.pop('evil', [])
            date_first_seen = element.pop('date_first_seen', datetime.datetime.utcnow())
            date_last_seen = element.pop('date_last_seen', datetime.datetime.utcnow())

            if '_id' in element:
                del element['_id']

            # check if existing
            while True:
                try:
                    _element = self.elements.find_one({'value': element['value']})
                    break
                except Exception, e:
                    debug_output("Could not fetch %s: %s" % (element['value'], e), 'error')

            if _element != None:
                for key in element:
                    if key == 'tags': continue
                    _element[key] = element[key]
                _element['tags'] = list(set([t.strip().lower() for t in _element['tags'] + tags]))
                if evil != []:
                    _element['evil'] = _element['evil'] + evil
                element = _element
                new = False
            else:
                new = True
                element['tags'] = tags
                element['evil'] = evil

            if not new:
                debug_output("(updated %s %s)" % (element.type, element.value), type='model')
                assert element.get('date_created', None) != None
                if element.get('date_first_seen'):
                    if date_first_seen < element['date_first_seen']:
                        element['date_first_seen'] = date_first_seen
                else:  # deal with old elements that don't have date_first|last_seen
                    element['date_first_seen'] = date_first_seen
                    element['date_last_seen'] = date_last_seen
            else:
                debug_output("(added %s %s)" % (element.type, element.value), type='model')
                element['date_created'] = datetime.datetime.utcnow()
                element['next_analysis'] = datetime.datetime.utcnow()
                element['date_first_seen'] = date_first_seen
                element['date_last_seen'] = date_last_seen

            # tags are all lowercased and stripped
            element['tags'] = [t.lower().strip() for t in element['tags']]

            while True:
                try:
                    self.elements.save(element)
                    break
                except pymongo.errors.DuplicateKeyError as e:
                    break
                except Exception as e:
                    debug_output("Could not save %s: %s (%s)" % (element, e, type(e)), 'error')

                # end of critical section

        assert element['date_created'] != None

        if not with_status:
            return element
        else:
            return element, new

    def add_text(self, text, tags=[]):

        added = []
        for t in text:
            if t:
                elt = None
                if t.strip() != "":
                    if is_url(t):
                        elt = Url(is_url(t), [])
                    elif is_ip(t):
                        elt = Ip(is_ip(t), [])
                    elif is_hostname(t):
                        elt = Hostname(is_hostname(t), [])
                    if elt:
                        elt['tags'] = tags
                        added.append(self.save(elt))

        if len(added) == 1:
            return added[0]
        else:
            return added

    # ---- remove operations ----

    def remove_element(self, element):
        self.remove_connections(element['_id'])
        return self.elements.remove({'_id': element['_id']})

    def remove_by_id(self, element_id):
        self.remove_connections(element_id)
        return self.elements.remove({'_id': ObjectId(element_id)})

    def remove_by_value(self, element_value):
        e = self.elements.find({'value': element_value})
        self.remove_connections(e['_id'])
        return self.elements.remove({'value': element_value})

    def remove_connections(self, element_id):
        self.graph.remove({'$or': [{'src': element_id}, {'dst': element_id}]})

    # ============= clear / list db ================

    def clear_db(self):
        for c in self._db.collection_names():
            if c in ['elements', 'graph', 'sniffer_sessions', 'feeds', 'history']:  # if c != "system.indexes":
                self._db[c].drop()

    def list_db(self):
        for e in self.elements.find():
            debug_output(e)

    # ============= search history =================

    def add_to_history(self, query):
        if query.lower().strip() != '':
            old = self.history.find_one({'query': query})
            now = datetime.datetime.utcnow()
            if old:
                old['last_searched'] = now
                old['hits'] = old['hits'] + 1
                self.history.save(old)
            else:
                self.history.save({'query': query, "first_searched": now, 'last_searched': now, 'hits': 1})

    def get_history(self, limit=10):
        return list(self.history.find(limit=10, sort=[('last_searched', pymongo.DESCENDING)]))

    # ============ sniffer operations ==============

    def save_sniffer_session(self, session):
        session_data = session.flow_status(include_payload=True, encoding='binary')
        session_data['nodes'] = session.nodes
        session_data['edges'] = session.edges

        dict = {
            'date_created': session.date_created,
            'name': session.name,
            'filter': session.filter,
            'intercept_tls': session.intercept_tls,
            'pcap': session.pcap,
            'pcap_filename': session.pcap_filename,
            'packet_count': session.packet_count,
            'session_data': bson_dumps(session_data),
            'public': session.public,
        }

        if not session.id:
            # we're creating a new session
            dict['_id'] = ObjectId()
            session.id = dict['_id']
        else:
            dict['_id'] = session.id

        self.sniffer_sessions.save(dict)
        return str(session.id)

    def get_sniffer_session(self, session_id):
        session = self.sniffer_sessions.find_one(ObjectId(session_id))
        return session

    def get_sniffer_sessions(self, private=True, username=None, filter={}, page=0, max=50):
        if username:
            user_sessions = [ObjectId(id) for id in self.um.get_user(username=username).sniffer_sessions]
        else:
            user_sessions = {}

        if not private:
            filter = {'$or': [{'public': True}, {'_id': {'$in': user_sessions}}]}
        else:
            filter = {'_id': {'$in': user_sessions}}

        while True:
            try:
                session_list = list(self.sniffer_sessions.find(filter, skip=page, limit=max, sort=[('date_created', pymongo.DESCENDING)]))
                break
            except Exception, e:
                debug_output("{}".format(e), 'error')

        return session_list

    def del_sniffer_session(self, session, sniffer_dir):

        filename = session.pcap_filename

        try:
            os.remove(sniffer_dir + "/" + filename)
        except Exception, e:
            print e

        self.sniffer_sessions.remove({'name': session.name})

        return True

    # =========== Feed operations =====================

    def add_feed(self, feed):
        elts = feed.get_info()

        for e in elts:
            self.malware_add(e, e['tags'])

    def feed_last_run(self, feed_name):
        self.feeds.update({'name': feed_name}, {'$set': {'last_run': datetime.datetime.utcnow()}}, upsert=True)

    def get_feed_progress(self, feed_names):
        feeds = [f for f in self.feeds.find({'name': {'$in': feed_names}})]
        return feeds

    def get_feeds(self):
        feeds = [f['name'] for f in self.feeds.find()]
        return feeds

    # =========== Modules operations =====================

    def load_module_entry(self, session_id, module_name):
        entry = self.modules.find_one({'session_id': session_id, 'name': module_name})
        if entry:
            return entry['entry']
        else:
            return {}

    def save_module_entry(self, session_id, module_name, entry, timeout=None):
        asd = self.modules.update({'name': module_name, 'session_id': session_id}, {'name': module_name, 'session_id': session_id, 'entry': entry, 'timeout': timeout}, upsert=True)

