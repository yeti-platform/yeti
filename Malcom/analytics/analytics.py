import dateutil, time, threading, pickle, gc, datetime, os
from bson.objectid import ObjectId
from multiprocessing import Process, Queue
import Queue as ExceptionQueue

import adns

from Malcom.auxiliary.toolbox import *
from Malcom.model.model import Model
from Malcom.model.datatypes import Hostname, Ip, Url, As
from Malcom.analytics.messenger import AnalyticsMessenger
from Malcom.auxiliary.async_resolver import AsyncResolver




class Worker(Process):

	def __init__(self, queue, name=None):
		super(Worker, self).__init__()
		self.queue = queue
		self.engine = None
		self.work = False
		if name: self.name = name

		
	def run(self):
		self.work = True
		try:
			while self.work:
				
				t0 = datetime.datetime.now()
				# debug_output("[%s | PID %s] FETCHING NEW ELT (size: %s)" % (self.name, os.getpid(), self.queue.qsize()), type='error')
				try:
					elt = self.queue.get(block=False, timeout=0.5)
				except ExceptionQueue.Empty, e:
					debug_output("[%s | PID %s] QUEUE EMPTY (size: %s, %s)"% (self.name, os.getpid(), self.queue.qsize(), self.queue.empty()), type='error')
					# if self.queue.qsize() < 1:
					# 	break
					# else:
					# 	time.sleep(0.5)
					# 	continue

				# print "CCCCCC", self.name
				elt = pickle.loads(elt)
				if elt == None:
					break
				# print "DDDDDDD", self.name
				# print elt

				# debug_output("[%s | PID %s] Started work on %s %s. Queue size: %s" % (self.name, os.getpid(), elt['type'], elt['value'], self.queue.qsize()), type='analytics')
				type_ = elt['type']
				tags = elt['tags']

				if type_ == 'hostname':
					tt0 = datetime.datetime.now()
					self.engine.ar.submit(elt['value'])
					# debug_output("[%s | PID %s] PUT ADNS IN QUEUE (%s)" % (self.name, os.getpid(), datetime.datetime.now() -tt0), type='error')

				new = elt.analytics()
				# debug_output("[%s | PID %s] ANALYTICS DONE (%s NEW)" % (self.name, os.getpid(), len(new)), type='error')
				self.engine.process_new(elt, new)
				# debug_output("[%s | PID %s] NEW PROCESSED" % (self.name, os.getpid()), type='error')
				self.engine.save_element(elt, tags)
				# debug_output("[%s | PID %s] NEW SAVED" % (self.name, os.getpid()), type='error')

				self.engine.progress += 1
				# self.engine.notify_progress(elt['value'])
				# debug_output("[%s | PID %s] NOTIFIED" % (self.name, os.getpid()), type='error')

				t = datetime.datetime.now()
				open('logfile.txt', 'a+').write("%s -> %s\n" %(t-t0, elt['value']))

			# debug_output("[%s | PID %s] EXITING" % (self.name, os.getpid()), type='error')
			return

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
		self.process_lock = threading.Lock()
		self.status = "Inactive"
		self.thread = None
		self.progress = 0
		self.workers = []
		self.elements_queue = None
		self.adns_results = None
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

	def bulk_asn(self, items=1000):

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
		self.ar = AsyncResolver(self.add_adns_result, max_reqs=500)
		self.ar.start()
		self.adns_results = []
		
		while self.run_analysis:
			debug_output("Analytics hearbeat")
			
			self.active_lock.acquire()	
			if self.run_analysis:
				self.process(1000)
			self.active_lock.release()

			try:
				time.sleep(1)
			except KeyboardInterrupt:
				self.run_analysis = False
			
			if self.once: self.run_analysis = False; self.once = False

		self.ar.stop()

	def stop(self):
		self.run_analysis = False
		for w in self.workers:
			try:
				w.stop()
			except Exception, e:
				pass
		try:
			while True:
				self.elements_queue.get(False)
		except Exception, e:
			pass

	def add_adns_result(self, host, rtype, answer):
		self.adns_results.append((host, rtype, answer))

	def process_adns_results(self):
		time.sleep(1)
		# print len(self.adns_results)
		while len(self.adns_results) > 0:
			host, rtype, answer = self.adns_results.pop()
			# print host, rtype, answer
			
			host = self.data.get(value=host)
			hname = host['value']
			# print "rtype:%s\nhost:%s\nanswer:%s" % (rtype, host, answer)

			if rtype == adns.rr.CNAME: # cname
				# print answer
				self.process_new(host, [('CNAME', Hostname(hostname=cname.lower())) for cname in answer[3]])
				
			if rtype == adns.rr.A:
				records = [('A', Ip(ip=ip)) for ip in answer[3]]
				self.process_new(host, records)
			
			if rtype == adns.rr.MX:
				mx_records = {}

				for mx in answer[3]:
					# print mx
					if mx[1][0] in ['', None]: continue
					mx_records[mx[1][0].lower()] = (mx[0], [ip[1] for ip in mx[1][2]])
			
				# print mx_records
				new_mx = [("MX (%s)" % mx_records[mx_srv][0], self.data.add_text([mx_srv.lower()])) for mx_srv in mx_records]
				mx_hostnames = self.process_new(host, new_mx)

				for host in mx_hostnames:
					ips = mx_records[host['value']][1]
					self.process_new(host, [('A', Ip(ip=ip)) for ip in ips])
				
			if rtype == adns.rr.NS:
				ns_records = {}
				for ns in answer[3]:
					# print ns
					if ns[2]: ips = [ip[1] for ip in ns[2]]
					else: ips = []
					ns_records[ns[0].lower()] = (ns[0].lower(), ips)

				# print ns_records
				new_ns = [("NS", Hostname(hostname=hname.lower())) for hname in ns_records]
				ns_hostnames = self.process_new(host, new_ns)

				for host in ns_hostnames:
					ips = ns_records[host['value']][1]
					if ips:
						self.process_new(host, [('A', Ip(ip=ip)) for ip in ips])


	def process_new(self, elt, new):
		self.process_lock.acquire()
		last_connect = elt.get('date_updated', datetime.datetime.utcnow())
		new_elts = []
		for n in new:
			if not n[1]: continue
			saved = self.save_element(n[1])
			
			# do the link
			conn = self.data.connect(elt, saved, n[0])
			first_seen = conn['first_seen']
			last_seen = conn['last_seen']

			# update date updated if there's a new connection
			if first_seen > last_connect:
				last_connect = first_seen

			# this will change updated time
			elt['date_updated'] = last_connect

			new_elts.append(saved)

		self.process_lock.release()
		return new_elts
			
			

	def process(self, batch_size=1000):
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

			# build process Queue
			self.elements_queue = Queue(0)
			
			# add elements to Queue
			for elt in results:
				# print pickle.dumps(elt), self.elements_queue.qsize()
				self.elements_queue.put(pickle.dumps(elt))
				total_elts += 1
				work_done = True
			# print "YAY1"

			for i in range(self.max_workers):
				self.elements_queue.put(pickle.dumps(None))

			# print "YAY"
			

			# start workers
			workers = []
			for i in range(self.max_workers):
				w = Worker(self.elements_queue, name="Worker %s" % i)
				w.engine = self
				w.start()
				workers.append(w)

			self.workers = workers

			for w in self.workers:
				try:
					w.join()
				except KeyboardInterrupt:
					self.run_analysis = False
			
			debug_output("Workers have joined")

			# regroup ASN analytics and ADNS analytics
			if self.run_analysis:
				self.bulk_asn()
				self.process_adns_results()
				self.active = False
		
		now = datetime.datetime.utcnow()
		
		if total_elts > 0:
			debug_output("Analyzed %s elements in %s" % (total_elts, str(now-then)) )
		if self.run_analysis == True:
			self.notify_progress("Inactive")
		

	