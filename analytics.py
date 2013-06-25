from flask import Flask

from toolbox import *
import dateutil
import logging
import time
import threading
from model import Model
from datatypes.element import Hostname, Ip, Url, As


class Worker(threading.Thread):

	def __init__(self, elt, engine):
		threading.Thread.__init__(self)
		self.elt = elt
		self.engine = engine
		self.thread = None
		

	def run(self):
		debug_output("Started thread on %s %s" % (self.elt['type'], self.elt['value']))

		etype = self.elt['type']
		context = self.elt['context']
		new = self.elt.analytics()
		for n in new:
			elt = self.engine.data.exists(n[1])
			if not elt:
				added = self.engine.add(n[1], context)
			else:
				added = self.engine.add(elt, context)

			#do the link
			self.engine.data.connect(self.elt, added, n[0])
		
		self.engine.add(self.elt,context)
		self.engine.progress += 1
		self.engine.websocket_lock.acquire()
		self.engine.notify_progress()
		self.engine.websocket_lock.release()
		self.engine.max_threads.release()

		



class Analytics:

	def __init__(self):
		self.data = Model()
		self.max_threads = threading.Semaphore(20)
		self.active = False
		self.websocket = None
		self.thread = None
		self.websocket_lock = threading.Lock()

	def add_text(self, text, context=[]):
		
		for t in text:
			elt = None
			if t.strip() != "":
			
				if is_ip(t):
					elt = Ip(t, [])
				elif is_url(t):
					elt = Url(t, [])
				elif is_hostname(t):
					elt = Hostname(t, [])

				if elt:
					return self.add(elt, context)
		

	def add(self, element, context):

		element.upgrade_context(context)
		_id = self.data.save(element)
		return self.data.find_one(_id)


	# graph function
	def add_artifacts(self, data, context=[]):
		artifacts = find_artifacts(data)
		
		added = []
		for url in artifacts['urls']:
			added.append(self.data.save(url, context))

		for hostname in artifacts['hostnames']:
			added.append(self.data.hostname_add(hostname, context))

		for ip in artifacts['ips']:
			added.append(self.data.ip_add(ip, context))

		return added        


	# elements analytics

	def malware_analytics(self, malware, context):
		debug_output("(malware analytics for %s)" % malware['url'])

		for c in context:
			if c not in malware['context']:
				malware['context'].append(c)

		if 'url' in malware:
			new = self.data.url_add(malware['url'], context)
			self.data.connect(malware,new)


	def bulk_asn(self):
		results = self.data.elements.find({ 'type': 'ip' })
		elts = []
		ips = []
		debug_output("(getting ASNs for %s IPs)" % results.count())
		for r in results:
			elts.append(r)
			ips.append(r['value'])

		as_info = get_net_info(ips)
		if not as_info:
			return

		for i in range(len(ips)):
			_as = As.from_dict(as_info[i])
			_as['last_analysis'] = datetime.datetime.now()
			_as['date_updated'] = datetime.datetime.now()
			new = self.add(_as, elts[i]['context'])
			#elts[i]['as'] = as_info[i]['as']
			self.data.connect(elts[i], new, 'net_info')


	def process(self):
		if self.thread:
			if self.thread.is_alive():
				return
		self.thread = threading.Thread(None, self.process_thread, None)
		self.thread.start()

	def notify_progress(self):
		if self.progress != self.total:
			send_msg(self.websocket, {'progress': '%s/%s' %(self.progress, self.total)})
		else:
			send_msg(self.websocket, {'status': 0})

	def process_thread(self):
		
		self.active = True
		results = self.data.elements.find(
			{ '$or': [
						{ 'last_analysis': {"$lt": datetime.datetime.now() - datetime.timedelta(1)} },
						{ 'last_analysis': None },
					]
			}
		)

		while results.count() > 0:

			stack_lock = threading.Lock()

			results = [r for r in results]
			debug_output("################## Will deal with %s results" % len(results))
			threads = []

			# status reporting
			self.total = len(results)
			self.progress = 0

			while len(results) > 0:

				self.max_threads.acquire()
				stack_lock.acquire()
				elt = results.pop()
				stack_lock.release()
				thread = Worker(elt, self)
				threads.append(thread)
				thread.start()

			for t in threads:
				t.join()

			debug_output("################## used %s threads for this loop" % len(threads))

			results = self.data.elements.find(
				{ '$or': [
							{ 'last_analysis': {"$lt": datetime.datetime.now() - datetime.timedelta(1)} },
							{ 'last_analysis': None },
						]
				}
			)

		# regroup ASN analytics to make only 1 query to Cymru
		self.bulk_asn()
		self.active = False


		
