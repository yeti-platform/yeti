#from gevent import monkey; monkey.patch_socket(); monkey.patch_time();

from flask import Flask
import Malcom
import dateutil, time, threading, pickle, gc, datetime, os
from bson.objectid import ObjectId
from multiprocessing import Process, Queue

from Malcom.auxiliary.toolbox import *
from Malcom.model.model import Model
from Malcom.model.datatypes import Hostname, Ip, Url, As
from Malcom.analytics.messenger import AnalyticsMessenger

class Worker(Process):

	def __init__(self, queue):
		super(Worker, self).__init__()
		self.queue = queue
		self.engine = None
		self.work = False
		
	def run(self):
		self.work = True
		try:
			while self.work:
	
				elt = self.queue.get()

				if elt == None:
					break

				elt = pickle.loads(elt)

				debug_output("[%s | PID %s] Started work on %s %s. Queue size: %s" % (self.name, os.getpid(), elt['type'], elt['value'], self.queue.qsize()), type='analytics')
				etype = elt['type']
				tags = elt['tags']

				new = elt.analytics()
				last_connect = elt.get('date_updated', datetime.datetime.utcnow())
				
				for n in new:
					saved = self.engine.save_element(n[1])
					# do the link
					conn = self.engine.data.connect(elt, saved, n[0])
					first_seen = conn['first_seen']
					last_seen = conn['last_seen']

					# update date updated if there's a new connection
					if first_seen > last_connect:
						last_connect = first_seen

				# this will change updated time
				elt['date_updated'] = last_connect
				self.engine.save_element(elt, tags)

				self.engine.progress += 1
				self.engine.notify_progress(elt['value'])
			return
			print "Worker exiting"

		except Exception, e:
			debug_output("An error occured in [%s | PID %s]: %s" % (self.name, os.getpid(), e), type="error")
		except KeyboardInterrupt, e:
			pass

	def stop(self):
		self.work = False



class Analytics(Process):

	def __init__(self, max_workers=4):
		super(Analytics, self).__init__()
		self.data = Model()
		self.max_workers = max_workers
		self.active = False
		self.active_lock = threading.Lock()
		self.status = "Inactive"
		self.websocket = None
		self.thread = None
		self.progress = 0
		self.total = 0
		self.workers = []
		self.elements_queue = None
		self.once = False


	def save_element(self, element, tags=[], with_status=False):
		element.upgrade_tags(tags)
		return self.data.save(element, with_status=with_status)
		
	# graph function
	def add_artifacts(self, data, tags=[]):
		artifacts = find_artifacts(data)
		
		added = []
		for url in artifacts['urls']:
			added.append(self.save_element(url, tags))

		for hostname in artifacts['hostnames']:
			added.append(self.save_element(hostname, tags))

		for ip in artifacts['ips']:
			added.append(self.save_element(ip, tags))

		return added        


	# elements analytics

	def bulk_asn(self, items=1000):

		last_analysis = {'$or': [
									{ 'last_analysis': {"$lt": datetime.datetime.utcnow() - datetime.timedelta(days=7)} },
									{ 'last_analysis': None },
								]
						}

		nobgp = {"$or": [{'bgp': None}, last_analysis ]}

		total = self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]}).count()
		done = 0
		results = [r for r in self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]})[:items]]

		while len(results) > 0:
		
			ips = []
			debug_output("(getting ASNs for %s IPs - %s/%s done)" % (len(results), done, total), type='analytics')
			
			for r in results:
				ips.append(r)

			as_info = {}
			
			try:
				as_info = get_net_info_shadowserver(ips)
			except Exception, e:
				debug_output("Could not get AS for IPs: %s" % e)
			
			if as_info == {} or as_info == None:
				debug_output("as_info empty", 'error')
				return

			for ip in as_info:
				
				_as = as_info[ip]
				_ip = self.data.find_one({'value': ip})

				if not _ip:
					return

				del _as['ip']
				for key in _as:
					if key not in ['type', 'value', 'tags']:
						_ip[key] = _as[key]
				del _as['bgp']

				_as = As.from_dict(_as)

				# commit any changes to DB
				_as = self.save_element(_as)
				_ip['last_analysis'] = datetime.datetime.utcnow()
				_ip = self.save_element(_ip)
			
				if _as and _ip:
					self.data.connect(_ip, _as, 'net_info')
			done += len(results)
			results = [r for r in self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]})[:items]]

	def bulk_dns(self):
		pass




	def single_graph_find(self, elt, query, depth=2):
		chosen_nodes = []
		chosen_links = []
		
		if depth > 0:
			# get a node's neighbors
			neighbors_n, neighbors_l = self.data.get_neighbors_elt(elt, include_original=False)
			
			for i, node in enumerate(neighbors_n):
				# for each node, find evil (recursion)
				en, el = self.single_graph_find(node, query, depth=depth-1)
				
				# if we found evil nodes, add them to the chosen_nodes list
				if len(en) > 0:
					chosen_nodes += [n for n in en if n not in chosen_nodes] + [node]
					chosen_links += [l for l in el if l not in chosen_links] + [neighbors_l[i]]
		else:
			
			# if recursion ends, then search for evil neighbors
			neighbors_n, neighbors_l = self.data.get_neighbors_elt(elt, {query['key']: {'$in': [query['value']]}}, include_original=False)
			
			# return evil neighbors if found
			if len(neighbors_n) > 0:
				chosen_nodes += [n for n in neighbors_n if n not in chosen_nodes]
				chosen_links += [l for l in neighbors_l if l not in chosen_links]
				
			# if not, return nothing
			else:
				chosen_nodes = []
				chosen_links = []

		return chosen_nodes, chosen_links

	def notify_progress(self, msg):
		if self.active:
			msg = "Working - %s" % msg
		else:
			msg = "Inactive"

		self.messenger.broadcast(msg, 'analytics', 'analyticsUpdate')

	def run(self):
		self.run_analysis = True
		
		self.messenger = AnalyticsMessenger(self)

		while self.run_analysis:
			debug_output("Analytics hearbeat")
			
			self.active_lock.acquire()			
			if self.run_analysis:
				self.process(10000)
			self.active_lock.release()

			try:
				time.sleep(1)
			except KeyboardInterrupt:
				self.run_analysis = False
			
			if self.once: self.run_analysis = False; self.once = False

	def stop(self):
		self.run_analysis = False
		for w in self.workers:
			try:
				w.stop()
			except Exception, e:
				pass

		self.join()

		try:
			while True:
				self.elements_queue.get(False)
		except Exception, e:
			pass
			

	def process(self, batch_size=10000):
		if self.thread:
			if self.thread.is_alive():
				return

		then = datetime.datetime.utcnow()

		self.workers = []
		self.work_done = False

		query = {'next_analysis' : {'$lt': datetime.datetime.utcnow()}}
		results = [r for r in self.data.elements.find(query)[:batch_size]]
		total_elts = 0

		if len(results) > 0:
			self.active = True

			# build process Queue (10000 elements max)
			self.elements_queue = Queue(batch_size+self.max_workers)
			
			# add elements to Queue
			for elt in results:
				self.elements_queue.put(pickle.dumps(elt))
				total_elts += 1
				work_done = True

			for i in range(self.max_workers):
				self.elements_queue.put(None)

			# start workers
			workers = []
			for i in range(self.max_workers):
				w = Worker(self.elements_queue)
				w.engine = self
				w.start()
				workers.append(w)

			self.workers = workers

			for w in self.workers:
				try:
					w.join()
				except KeyboardInterrupt:
					self.run_analysis = False
				
			# regroup ASN analytics to make only 1 query to Cymru / Shadowserver
			self.bulk_asn()
			self.active = False
		
		now = datetime.datetime.utcnow()
		
		if total_elts > 0:
			debug_output("Analyzed %s elements in %s" % (total_elts, str(now-then)) )
		if self.run_analysis == True:
			self.notify_progress("Inactive")
		

	