from pymongo import MongoClient
from pymongo.son_manipulator import SONManipulator
import dateutil
import pygeoip
import threading
from toolbox import *
from bson.objectid import ObjectId
from datatypes.element import Hostname, Url, Ip, As, Evil

def encode_datatype(datatype):
	return datatype.to_dict()

def decode_custom_ip(document):
	assert document['type'] == "ip"
	return Ip.from_dict(document)
	
def decode_custom_url(document):
	assert document['type'] == "url"
	return Url.from_dict(document)
	
def decode_custom_hostname(document):
	assert document['type'] == "hostname"
	return Hostname.from_dict(document)

def decode_custom_as(document):
	assert document['type'] == "as"
	return As.from_dict(document)

def decode_custom_evil(document):
	assert document['type'] == "evil"
	return Evil.from_dict(document)

class Transform(SONManipulator):
	def transform_incoming(self, son, collection):
		for (key, value) in son.items():
			if isinstance(value, Hostname) or isinstance(value, Ip) or isinstance(value, Url):
				son[key] = encode_datatype(value) #do static methods in each class
			elif isinstance(value, dict): # Make sure we recurse into sub-docs
				son[key] = self.transform_incoming(value, collection)
		return son


	def transform_outgoing(self, son, collection):
		if 'type' in son:
			if son['type'] == 'ip':
				return decode_custom_ip(son)
			if son['type'] == 'url':
				return decode_custom_url(son)
			if son['type'] == 'hostname':
				return decode_custom_hostname(son)
			if son['type'] == 'as':
				return decode_custom_as(son)
			if son['type'] == 'evil':
				return decode_custom_evil(son)
		else:
			return son


class Model:

	def __init__(self):
		self._connection = MongoClient()
		self._db = self._connection.cifpy_flask_new
		self._db.add_son_manipulator(Transform())
		self.elements = self._db.elements
		self.graph = self._db.graph
		self.history = self._db.history

		self.gi = pygeoip.GeoIP('geoIP/GeoLiteCity.dat')
		self.db_lock = threading.Lock()
		#print self.stats()

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
			print e

	
	def save(self, element):
		self.db_lock.acquire()
		elt = self.exists(element)

		if elt:
			element['_id'] = elt['_id']
			element.upgrade_context(elt['context'])
			element['date_updated'] = datetime.datetime.utcnow()
			print "(updated %s %s)" % (element.type, element.value)
		else:
			#element['context'] = context
			element['date_created'] = datetime.datetime.utcnow()
			print "(added %s %s to DB)" % (element.type, element.value)

		saved = self.elements.save(element)

		self.db_lock.release()
		return saved

	def remove(self, element_id):
		return self.elements.remove({'_id' : ObjectId(element_id)})

	def exists(self, element):
		return self.elements.find_one({ 'value': element.value })


	def connect(self, src, dst, attribs="", commit=True):

			if not src or not dst:
				exit()
			conn = self.graph.find_one({ 'src': ObjectId(src._id), 'dst': ObjectId(dst._id) })
			if conn:
				conn['attribs'] = attribs
			else:
				conn = {}
				conn['src'] = src._id
				conn['dst'] = dst._id
				conn['attribs'] = attribs   
				print "(linked %s to %s [%s])" % (str(src._id), str(dst._id), attribs)
			if commit:
				self.graph.save(conn)
			return conn

	def add_feed(self, feed):
		elts = feed.get_info()
	  
		for e in elts:
			self.malware_add(e,e['context'])

	def get_neighbors(self, elt, query={}):

		if not elt:
			return [], []

		# get all links to / from the required element

		new_edges = [n for n in self.graph.find({	'$or' : [
															{'src': elt['_id']},
															{'dst': elt['_id']}
													]})]

		# get all IDs of the new nodes that have been discovered
		s_src = set([e['src'] for e in new_edges])
		s_dst = set([e['dst'] for e in new_edges])

		ids = list(s_src | s_dst | set([elt['_id']]))
		
		# get the new node objects
		#nodes = [node for node in self.elements.find({ "_id" : { '$in' : ids }})]
		nodes = [node for node in self.elements.find( {'$and' : [{ "_id" : { '$in' : ids }}, query]})]

		# get nodes IDs
		nodes_id = [n['_id'] for n in nodes]

		# remove links for which a node was not compliant to query
		new_edges = [e for e in new_edges if e['src'] in nodes or e['dst'] in nodes_id]
		
		# get links for new nodes, in case we use them
		more_edges = [edge for edge in self.graph.find({'$or' : [
											{"src" : {'$in' : nodes_id }},
											{"dst" : {'$in' : nodes_id }}
											]}) if edge not in new_edges]

		

		destinations = [e['dst'] for e in new_edges]
		for n in nodes:
			n['group'] = 1
			n['incoming_links'] = destinations.count(n['_id'])

		new_edges.extend(more_edges)

		return nodes, new_edges


	def get_graph_for_elts(self, elts):
		edges = []
		
		ids = []
		for e in elts:

			new_edges = [n for n in self.graph.find({ '$or' : [
															{'src': e['_id']}, 
															{'dst': e['_id']}
															] })]
			
			while len(new_edges) > 0:
				edges.extend(new_edges)

				get_new_edges = []

				for edge in new_edges:
					get_new_edges.append(edge['dst'])
						 
				new_edges = [edge for edge in self.graph.find( {'$or' : [
																	{"src" : {'$in' : get_new_edges }},
																	{"dst" : {'$in' : get_new_edges }}
																	]}) if edge not in edges]

		s_src = set([e['src'] for e in edges])
		s_dst = set([e['dst'] for e in edges])

		ids = list(s_src | s_dst | set([n['_id'] for n in elts]))
		
		nodes = [node for node in self.elements.find({ "_id" : { '$in' : ids }})]

		

		

		idlist = [n['_id'] for n in nodes]

		ids = list(set([e['_id'] for e in edges]))
		edges = [e for e in self.graph.find({"_id" : { '$in': ids }})]
		destinations = [e['dst'] for e in edges]
		for n in nodes:
			n['group'] = 1
			n['incoming_links'] = destinations.count(n['_id'])

		for e in edges:
			e['source'] = idlist.index(e['src'])
			e['target'] = idlist.index(e['dst'])
			e['src']
			e['dst']


	

		return edges, nodes
		#return [], [nodes[0]]

 
