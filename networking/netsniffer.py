from scapy.all import *
from scapy.error import Scapy_Exception
import pwd, os, sys, time, threading
from bson.json_util import dumps
from toolbox import debug_output
from bson.objectid import ObjectId
from flow import Flow


types = ['hostname', 'ip', 'url', 'as', 'malware']

NOTROOT = "nobody"


class Sniffer():

	def __init__(self, analytics, name, remote_addr, filter, ifaces, ws=None):
		
		self.analytics = analytics
		self.name = name
		self.ws = ws
		self.ifaces = ifaces
		filter_ifaces = ""
		for i in ifaces:
			filter_ifaces += " and not host %s " % ifaces[i]
		self.filter = "ip and not host 127.0.0.1 and not host %s %s" % (remote_addr, filter_ifaces)
		#easier testing this way
		self.filter = "ip and not host 127.0.0.1 and not host %s" % (remote_addr)
		if filter != "":
			self.filter += " and (%s)" % filter
		self.stopSniffing = False
		
		self.thread = None
		self.pkts = []
		self.nodes = []
		self.edges = []
		self.nodes_ids = []
		self.nodes_values = []
		self.nodes_pk = []
		self.edges_ids = []
		self.flows = {}


	def load_pcap(self, pcap):
		debug_output("Loading PCAP from file...")
		timestamp = str(time.mktime(time.gmtime())).split('.')[0]
		filename = '/tmp/load-%s.cap' % timestamp
		#try:
		f = open(filename, 'wb')
		f.write(pcap)
		f.close()
		self.pkts += self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1, offline=filename)	
		debug_output("Loaded %s packets from file." % len(self.pkts))
		#except Exception, e:
		#	return e
		
		return True

	def run(self):
		debug_output("[+] Sniffing session %s started" % self.name)
		debug_output("[+] Filter: %s" % self.filter)
		self.stopSniffing = False
		self.pkts += self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1)	
		#except Exception, e:
		#	print e
		
		debug_output("[+] Sniffing session %s stopped" % self.name)

		return 

	def update_nodes(self):
		return { 'query': {}, 'nodes':self.nodes, 'edges': self.edges }

	def flow_status(self):
		data = {}
		data['flows'] = []
		for fid in self.flows:
			data['flows'].append(self.flows[fid].get_statistics())
		data['flows'] = sorted(data['flows'], key= lambda x: x['timestamp'])
		return data

	def start(self, remote_addr):
		self.thread = threading.Thread(None, self.run, None)
		self.thread.start()
		
	def stop(self):
		self.stopSniffing = True
		if self.thread:
			self.thread.join()
		time.sleep(0.5)
		return True
		

	def status(self):
		if self.thread:
			return self.thread.is_alive()
		else:
			return False


	def get_pcap(self):
		debug_output("Generating PCAP (length: %s)" % len(self.pkts))
		if len(self.pkts) == 0:
			return ""
		wrpcap("/tmp/temp.cap", self.pkts)
		pcap = open('/tmp/temp.cap').read()
		return pcap
	
	def checkIP(self, pkt):

		source = {}
		dest = {}
		new_elts = []
		new_edges = []

		if IP in pkt:
			source['ip'] = pkt[IP].src
			dest['ip'] = pkt[IP].dst
		else: return None, None

		if TCP in pkt or UDP in pkt:
			source['port'] = pkt[IP].sport
			dest['port'] = pkt[IP].dport
		else: return None, None

		src = source['ip']
		dst = dest['ip']

		if src not in self.nodes_values:
			src = self.analytics.add_text([src], ['sniffer', self.name])
			self.nodes_ids.append(src['_id'])
			self.nodes_values.append(src['value'])
			self.nodes.append(src)
			new_elts.append(src)
		else:
			src = [e for e in self.nodes if e['value'] == src][0]

		if dst not in self.nodes_values:
			dst = self.analytics.add_text([dst], ['sniffer', self.name])
			self.nodes_ids.append(dst['_id'])
			self.nodes_values.append(dst['value'])
			self.nodes.append(dst)
			new_elts.append(dst)
		else:
			dst = [e for e in self.nodes if e['value'] == dst][0]

		# if src['_id'] not in self.nodes_ids:
		# add to db
		# if dst['_id'] not in self.nodes_ids:
		# add to db
		# this is being done in the conditions above
			

		# don't save sniffing relations to the DB
		# conn = self.analytics.data.connect(src, elt, 'communication', True)

		oid = "$oid"
		conn = {'attribs': '%s > %s' %(source['port'], dest['port']), 'src': src['_id'], 'dst': dst['_id'], '_id': { oid: str(src['_id'])+str(dst['_id'])}}
		
		if conn not in self.edges:
			self.edges.append(conn)
			new_edges.append(conn)
		
		return new_elts, new_edges

	def checkDNS(self, pkt):

		new_elts = []
		new_edges = []

		# intercept DNS responses (these contain names and IPs)
		if DNS in pkt and pkt[IP].sport == 53:
			debug_output("[+] DNS reply caught (%s answers)" % pkt[DNS].ancount)
			
			for i in xrange(pkt[DNS].ancount): # cycle through responses and add records to graph

				if pkt[DNS].an[i].type != 1:
					debug_output('No A records in reply')
					continue

				hname = pkt[DNS].an[i].rrname
				ipaddr = pkt[DNS].an[i].rdata

				# check if hname ends with '.'

				if hname[-1:] == ".":
					hname = hname[:-1]
				
				# check if we haven't seen these already
				if hname not in self.nodes_values:
					_hname = self.analytics.add_text([hname], ['sniffer', self.name]) # log every discovery to db
					self.nodes_ids.append(_hname['_id'])
					self.nodes_values.append(_hname['value'])
					self.nodes.append(_hname)
					new_elts.append(_hname)
				else:
					_hname = [e for e in self.nodes if e['value'] == hname][0]

				if ipaddr not in self.nodes_values:
					_ipaddr = self.analytics.add_text([ipaddr], ['sniffer', self.name]) # log every discovery to db
					self.nodes_ids.append(_ipaddr['_id'])
					self.nodes_values.append(_ipaddr['value'])
					self.nodes.append(_ipaddr)
					new_elts.append(_ipaddr)
				else:
					_ipaddr = [e for e in self.nodes if e['value'] == ipaddr][0]

				debug_output("Caught DNS response %s: %s -> %s" % (i, _hname['value'], _ipaddr['value']))
				debug_output("Added %s, %s" %(hname, ipaddr))


				conn = {'attribs': 'A', 'src': _hname['_id'], 'dst': _ipaddr['_id'], '_id': { '$oid': str(_hname['_id'])+str(_ipaddr['_id'])}}
				if conn not in self.edges:
					self.edges.append(conn)
					new_edges.append(conn)

			#deal with the original DNS request
			question = pkt[DNS].qd.qname

			if question not in self.nodes_values:
				_question = self.analytics.add_text([question], ['sniffer', self.name]) # log it to db (for further reference)
				if _question:
					self.nodes_ids.append(_question['_id'])
					self.nodes_values.append(_question['value'])
					self.nodes.append(_question)
					new_elts.append(_question)

			else:
				_question = [e for e in self.nodes if e['value'] == question][0]
						

				# conn = self.analytics.data.connect(_question, elt, "resolve", True)
				# conn = {'attribs': 'query', 'src': _question['_id'], 'dst': _ipaddr['_id'], '_id': { '$oid': str(_hname['_id'])+str(_ipaddr['_id']) } }
				# if conn not in self.edges:
				# 		self.edges.append(conn)
				# 		new_edges.append(conn)

		return new_elts, new_edges
		
	def checkHTTP(self, flow):
		# extract elements from payloads

		new_elts = []
		new_edges = []

		http_elts = flow.extract_elements()
		
		if http_elts:

			url = self.analytics.add_text([http_elts['url']])
			if url['value'] not in self.nodes_values:
				self.nodes_ids.append(url['_id'])
				self.nodes_values.append(url['value'])
				self.nodes.append(url)
				new_elts.append(url)

			host = self.analytics.add_text([http_elts['host']])
			if host['value'] not in self.nodes_values:
				self.nodes_ids.append(host['_id'])
				self.nodes_values.append(host['value'])
				self.nodes.append(host)
				new_elts.append(host)
			
			# in this case, we can save the connection to the DB since it is not temporary
			conn = self.analytics.data.connect(host, url, "host")
			#conn = {'attribs': http_elts['method'], 'src': host['_id'], 'dst': url['_id'], '_id': { '$oid': str(host['_id'])+str(url['_id'])}}
			if conn not in self.edges:
				self.edges.append(conn)
				new_edges.append(conn)

		print new_elts, new_edges
		return new_elts, new_edges


	def handlePacket(self, pkt):

		self.pkts.append(pkt)

		elts = []
		edges = []

		new_elts, new_edges = self.checkIP(pkt)
		if new_elts:
			elts += new_elts
		if new_edges:
			edges += new_edges

		new_elts, new_edges = self.checkDNS(pkt)
		if new_elts:
			elts += new_elts
		if new_edges:
			edges += new_edges

		# do flow analysis here, if necessary
		if TCP in pkt or UDP in pkt:
			Flow.pkt_handler(pkt, self.flows)
			flow = self.flows[Flow.flowid(pkt)]
			self.send_flow_statistics(flow)	
			
			new_elts, new_edges = self.checkHTTP(flow)
			if new_elts:
				elts += new_elts
			if new_edges:
				edges += new_edges			

			# end flow analysis
		
		self.send_nodes(elts, edges)

	def send_flow_statistics(self, flow):
		data = {}
		data['flow'] = flow.get_statistics()
		data['type'] = 'flow_statistics_update'
		if self.ws:
			try:
				self.ws.send(dumps(data))
			except Exception, e:
				debug_output("Could not send flow statistics: %s" % e)

	def send_nodes(self, elts=[], edges=[]):
		data = { 'querya': {}, 'nodes':elts, 'edges': edges, 'type': 'nodeupdate'}
		try:
			if (len(elts) > 0 or len(edges) > 0) and self.ws:
				self.ws.send(dumps(data))
		except Exception, e:
			debug_output("Could not send nodes: %s" % e)
		
	def stop_sniffing(self):
		return self.stopSniffing

	def sniff(self, count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, stopperTimeout=None, stopper = None, *arg, **karg):
		"""Sniff packets
			sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

			  count: number of packets to capture. 0 means infinity
			  store: wether to store sniffed packets or discard them
				prn: function to apply to each packet. If something is returned,
					 it is displayed. Ex:
					 ex: prn = lambda x: x.summary()
			lfilter: python function applied to each packet to determine
					 if further action may be done
					 ex: lfilter = lambda x: x.haslayer(Padding)
			offline: pcap file to read packets from, instead of sniffing them
			timeout: stop sniffing after a given time (default: None)
			stopperTimeout: break the select to check the returned value of 
					 stopper() and stop sniffing if needed (select timeout)
			stopper: function returning true or false to stop the sniffing process
			L2socket: use the provided L2socket
		"""
		c = 0

		if offline is None:
			if L2socket is None:
				L2socket = conf.L2listen
			s = L2socket(type=ETH_P_ALL, *arg, **karg)
		else:
			s = PcapReader(offline)

		lst = []
		if timeout is not None:
			stoptime = time.time()+timeout
		remain = None

		if stopperTimeout is not None:
			stopperStoptime = time.time()+stopperTimeout
		remainStopper = None
		while 1:
			try:
				if not stopper:
					break

				if timeout is not None:
					remain = stoptime-time.time()
					if remain <= 0:
						break

				if stopperTimeout is not None:
					remainStopper = stopperStoptime-time.time()
					if remainStopper <=0:
						if stopper and stopper():
							break
						stopperStoptime = time.time()+stopperTimeout
						remainStopper = stopperStoptime-time.time()

					sel = select([s],[],[],remainStopper)
					if s not in sel[0]:
						if stopper and stopper():
							break
				else:
					sel = select([s],[],[],remain)

				if s in sel[0]:
					p = s.recv(MTU)
					if not stopper:
						break
					if p is None:
						break
					if lfilter and not lfilter(p):
						continue
					if store:
						lst.append(p)
					c += 1
					if prn:
						r = prn(p)
						if r is not None:
							print r
					if count > 0 and c >= count:
						break
			except KeyboardInterrupt:
				break
		s.close()
		return plist.PacketList(lst,"Sniffed")