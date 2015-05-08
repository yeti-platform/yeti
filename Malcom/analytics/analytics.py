import dateutil, time, threading, pickle, gc, datetime, os
from bson.objectid import ObjectId
from multiprocessing import Process#, JoinableQueue as Queue, Lock

import Queue as Queue
from threading import Thread, Lock

from Malcom.auxiliary.toolbox import *
from Malcom.model.model import Model
from Malcom.model.datatypes import Hostname, Ip, Url, As
from Malcom.analytics.messenger import AnalyticsMessenger

class Worker(Thread):

	def __init__(self, name=None, queue_lock=None, hostname_lock=None):
		super(Worker, self).__init__()
		self.engine = None
		self.work = False

		if name: self.name = name
		self.queue_lock = queue_lock
		self.hostname_lock = hostname_lock

		debug_output("[%s | PID %s] STARTING" % (self.name, os.getpid()))

		# deferred_queue = Queue()

	def work_sync(self, elt, tags):
		tt0 = datetime.datetime.now()
		new = elt.analytics()
		debug_output("[%s | PID %s | elt: %s] ANALYTICS DONE (%s NEW) (%s)" % (self.name, os.getpid(), elt['value'], len(new), datetime.datetime.now() -tt0), type='debug')
		self.engine.process_new(elt, new)
		debug_output("[%s | PID %s | elt: %s] NEW PROCESSED" % (self.name, os.getpid(), elt['value']), type='debug')
		self.engine.save_element(elt, tags)
		debug_output("[%s | PID %s | elt: %s] NEW SAVED" % (self.name, os.getpid(), elt['value']), type='debug')
		self.engine.progress += 1
		# self.engine.notify_progress(elt['value'])
		# debug_output("[%s | PID %s | elt: %s] NOTIFIED" % (self.name, os.getpid(), elt['value']), type='debug')

		# t = datetime.datetime.now()
		

	def work_async(self, elt, tags):
		# get analysis time out of the way
		elt['last_analysis'] = datetime.datetime.utcnow()
		elt['next_analysis'] = elt['last_analysis'] + datetime.timedelta(seconds=elt['refresh_period'])
		elt = self.engine.save_element(elt, tags)

		# do the actual analysis
		t = Thread(target=self.work_sync, args=(elt, tags))
		t.daemon = True
		t.start()
		
	def run(self):
		self.work = True
		try:
			while self.work:
				
				t0 = datetime.datetime.now()
				
				with self.queue_lock:
					debug_output("[%s | PID %s] WAITING FOR NEW ELT (size: %s)" % (self.name, os.getpid(), self.engine.elements_queue.qsize()), type='debug')
					elt = self.engine.elements_queue.get()

				elt = pickle.loads(elt)
				if elt == "BAIL":
					debug_output("[%s | PID %s] GOT BAIL MESSAGE" % (self.name, os.getpid()), type='debug')
					self.work = False
					continue
				
				with self.queue_lock:
					debug_output("[%s | PID %s] Started work on %s %s. Queue size: %s" % (self.name, os.getpid(), elt['type'], elt['value'], self.engine.elements_queue.qsize()), type='analytics')
				
				type_ = elt['type']
				tags = elt['tags']

				if type_ == 'hostname':
					self.work_async(elt, tags)
				else:
					self.work_sync(elt, tags)

				t = datetime.datetime.now()
				debug_output("Finished analyzing %s in %s" %(elt['value'], t-t0))
				with self.queue_lock:
					self.engine.elements_queue.task_done()

			debug_output("[%s | PID %s] EXITING\n" % (self.name, os.getpid()), type='error')
			with self.queue_lock:
				self.engine.elements_queue.task_done()
			return

		except Exception, e:
			debug_output("An error occured in [%s | PID %s]: %s\nelt info:\n%s" % (self.name, os.getpid(), e, elt), type="error")
			with self.queue_lock:
				self.engine.elements_queue.task_done()
			return

	def stop(self):
		self.work = False



class Analytics(Process):

	def __init__(self, max_workers=4, setup={}):
		super(Analytics, self).__init__()
		self.data = Model(setup)
		self.max_workers = max_workers
		self.active = False
		self.active_lock = threading.Lock()
		# self.process_lock = threading.Lock()
		self.status = "Inactive"
		self.thread = None
		self.progress = 0
		self.workers = []
		self.elements_queue = None
		self.once = False
		self.run_analysis = False


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

	def bulk_functions(self):
		self.bulk_asn()

	def bulk_asn(self, items=1000):
		debug_output("Running bulk ASN")
		last_analysis = {'$or': [
									{ 'next_analysis' : {'$lt': datetime.datetime.utcnow()}},
									{ 'last_analysis': None },
								]
						}

		nobgp = {"$or": [{'bgp': None}, last_analysis ]}

		total = self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]}).count()
		done = 0
		results = [r for r in self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]})[:items]]

		while len(results) > 0 and self.run_analysis:
		
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
				_ip['next_analysis'] = _ip['last_analysis'] + datetime.timedelta(seconds=_ip['refresh_period'])
				_ip = self.save_element(_ip)
			
				if _as and _ip:
					self.data.connect(_ip, _as, 'net_info')
					
			done += len(results)
			results = [r for r in self.data.elements.find({ "$and": [{'type': 'ip'}, nobgp]})[:items]]


	def notify_progress(self, msg):
		if self.active:
			msg = "Working - %s" % msg
		else:
			msg = "Inactive"

		self.messenger.broadcast(msg, 'analytics', 'analyticsUpdate')


	def run(self):

		self.run_analysis = True
		self.messenger = AnalyticsMessenger(self)
		
		self.elements_queue = Queue.Queue()
		self.queue_lock = Lock()
		
		self.hostnames = Queue.Queue()
		self.hostname_lock = Lock()

		while self.run_analysis:
			debug_output("Analytics hearbeat")

			self.active_lock.acquire()	
			if self.run_analysis:
				self.process(10000)
			self.active_lock.release()

			if self.once: self.run_analysis = False; self.once = False

			time.sleep(1)
		
	def stop(self):
		self.run_analysis = False
		for w in self.workers:
			try:
				w.stop()
			except Exception, e:
				pass

	def process_new(self, elt, new):
		# self.process_lock.acquire()
		last_connect = elt.get('date_updated', datetime.datetime.utcnow())
		new_elts = []
		for n in new:
			if not n[1]: continue
			saved = self.save_element(n[1])
			
			# do the link
			conn = self.data.connect(elt, saved, n[0])
			if not conn: continue
			first_seen = conn.get('first_seen', datetime.datetime.utcnow())
			conn['first_seen'] = first_seen
			last_seen = conn['last_seen']

			# update date updated if there's a new connection
			if first_seen > last_connect:
				last_connect = first_seen

			# this will change updated time
			elt['date_updated'] = last_connect

			new_elts.append(saved)

		# self.process_lock.release()
		return new_elts


	def process(self, batch_size=2000):
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

			# start workers
			self.queue_lock = Lock()
			workers = []
			for i in range(self.max_workers):
				w = Worker(name="Worker %s" % i, queue_lock=self.queue_lock, hostname_lock=self.hostname_lock)
				w.engine = self
				w.start()
				workers.append(w)

			self.workers = workers

			# add elements to Queue
			for elt in results:
				self.elements_queue.put(pickle.dumps(elt))
				total_elts += 1
				work_done = True

			for i in range(self.max_workers):
				self.elements_queue.put(pickle.dumps("BAIL"))

			self.elements_queue.join()
			
			debug_output("Workers have joined")

			# regroup ASN analytics and ADNS analytics
			if self.run_analysis:
				self.bulk_functions()
				self.active = False
		
		now = datetime.datetime.utcnow()
		
		if total_elts > 0:
			debug_output("Analyzed %s elements in %s" % (total_elts, str(now-then)) )
		if self.run_analysis == True:
			self.notify_progress("Inactive")
