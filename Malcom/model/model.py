from pymongo import MongoClient
from pymongo.son_manipulator import SONManipulator
import dateutil
import pygeoip
import threading
from Malcom.auxiliary.toolbox import *
from bson.objectid import ObjectId
from Malcom.model.datatypes import Hostname, Url, Ip, As, Evil, DataTypes


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

	def __init__(self):
		self._connection = MongoClient()
		self._db = self._connection.malcom
		self._db.add_son_manipulator(Transform())
		self.elements = self._db.elements
		self.graph = self._db.graph
		self.history = self._db.history

		self.gi = pygeoip.GeoIP('Malcom/auxiliary/geoIP/GeoLiteCity.dat')
		self.db_lock = threading.Lock()

		# create indexes
		self.rebuild_indexes()

	def rebuild_indexes(self):
		# create indexes
		debug_output("Rebuliding indexes...", 'model')
		self.elements.ensure_index([('date_created', -1), ('value', 1)])
		self.elements.ensure_index('value')
		self.elements.ensure_index('tags')
		self.graph.ensure_index([('src', 1), ('dst', 1)])
		self.graph.ensure_index('src')
		self.graph.ensure_index('dst')

	def stats(self):
		stats = "DB loaded with %s elements\n" % self._db.elements.count()
		stats += "Graph has %s edges" % self._db.graph.count()
		return stats

	def find(self, query={}):
		return self.elements.find(query)

	def find_one(self, oid):
		return self.elements.find_one(oid)

	def clear_db(self):
		for c in self._db.collection_names():
			if c != "system.indexes":
				self._db[c].remove()
	
	def list_db(self):
		for e in self.elements.find():
			debug_output(e)

	
	def save(self, element, with_status=False):
		
		self.db_lock.acquire()
		#elt = self.exists(element)
	
		tags = element['tags']
		del element['tags'] # so tags in the db do not get overwritten

		if '_id' in element:
			del element['_id']

		status = self.elements.update({'value': element['value']}, {"$set" : element, "$addToSet": {'tags' : {'$each': tags}}}, upsert=True)
		saved = self.elements.find({'value': element['value']})

		assert(saved.count() == 1) # check that elements are unique in the db
		saved = saved[0]

		if status['updatedExisting'] == True:
			debug_output("(updated %s %s)" % (saved.type, saved.value), type='model')
		else:
			debug_output("(added %s %s)" % (saved.type, saved.value), type='model')
			saved['date_created'] = datetime.datetime.utcnow()

		saved['date_updated'] = datetime.datetime.utcnow()

		self.elements.save(saved)
		assert saved['date_created'] != None and saved['date_updated'] != None

		self.db_lock.release()

		if not with_status:
			return saved
		else:
			return saved, status

	def remove(self, element_id):
		return self.elements.remove({'_id' : ObjectId(element_id)})

	def exists(self, element):
		return self.elements.find_one({ 'value': element.value })


	def connect(self, src, dst, attribs="", commit=True):

			if not src or not dst:
				return None
			
			conn = self.graph.find_one({ 'src': ObjectId(src._id), 'dst': ObjectId(dst._id) })
			if conn:
				conn['attribs'] = attribs
			else:
				conn = {}
				conn['src'] = src._id
				conn['dst'] = dst._id
				conn['attribs'] = attribs   
				debug_output("(linked %s to %s [%s])" % (str(src._id), str(dst._id), attribs), type='model')
			if commit:
				self.graph.save(conn)
			return conn

	def add_feed(self, feed):
		elts = feed.get_info()
	  
		for e in elts:
			self.malware_add(e,e['tags'])

	def get_neighbors_id(self, elts, query={}, include_original=True):

		original_ids = [e['_id'] for e in elts]

		new_edges = self.graph.find({'$or': [
				{'src': {'$in': original_ids}}, {'dst': {'$in': original_ids}}
			]})
		_new_edges = self.graph.find({'$or': [
				{'src': {'$in': original_ids}}, {'dst': {'$in': original_ids}}
			]})


		ids = {}

		for e in _new_edges:
			ids[e['src']] = e['src']
			ids[e['dst']] = e['dst']

		ids = [i for i in ids]

		if include_original:
			q = {'$and': [{'_id': {'$in': ids}}, query]}
			original = {'$or': [q, {'_id': {'$in': original_ids}}]}
			new_nodes = self.elements.find(original)
		else:
			new_nodes = self.elements.find({'$and': [{'_id': {'$in': ids}}, query]})

		new_nodes = [n for n in new_nodes]
		new_edges = [e for e in new_edges]
		
		return new_nodes, new_edges
			

	def get_neighbors_elt(self, elt, query={}, include_original=True):

		if not elt:
			return [], []

		d_new_edges = {}
		new_edges = []
		d_ids = { elt['_id']: elt['_id'] }

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
		for node in self.elements.find( {'$and' : [{ "_id" : { '$in' : ids }}, query]}):
			nodes[node['_id']] = node
		
		# get incoming links (node weight)
		destinations = [d_new_edges[e]['dst'] for e in d_new_edges]
		for n in nodes:
			nodes[n]['incoming_links'] = destinations.count(nodes[n]['_id'])

		# get nodes IDs
		nodes_id = [nodes[n]['_id'] for n in nodes]
		# get links for new nodes, in case we use them
		for e in self.graph.find({'src': { '$in': nodes_id }}):
			d_new_edges[e['_id']] = e
		for e in self.graph.find({'dst': { '$in': nodes_id }}):
			d_new_edges[e['_id']] = e

		# if not include_original:
		# 	del nodes[elt['_id']]
		
		# create arrays
		new_edges = [d_new_edges[e] for e in d_new_edges]
		nodes = [nodes[n] for n in nodes]

		# display 
		for e in nodes:
			e['fields'] = e.display_fields

		return nodes, new_edges

 
