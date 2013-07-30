from scapy.all import *
import threading
import pwd, os, sys, time
from bson.json_util import dumps
from malcom import debug_output
from bson.objectid import ObjectId



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
		self.nodes_pk = []
		self.edges_ids = []


	def run(self):
		debug_output("[+] Sniffing session %s started" % self.name)
		debug_output("[+] Filter: %s" % self.filter)
		self.pkts += self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1)	
		debug_output("[+] Sniffing session %s stopped" % self.name)

		return 

	def update(self, session_name='default'):
		return { 'query': {}, 'nodes':self.nodes, 'edges': self.edges }

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

		src = self.analytics.add_text([src], ['sniffer', self.name])
		dst = self.analytics.add_text([dst], ['sniffer', self.name])

		if src['_id'] not in self.nodes_ids:
			self.nodes_ids.append(src['_id'])
			self.nodes.append(src)
			new_elts.append(src)

		if dst['_id'] not in self.nodes_ids:
			self.nodes_ids.append(dst['_id'])
			self.nodes.append(dst)
			new_elts.append(dst)

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

		# intercept DNS responses
		if DNS in pkt and pkt[IP].sport == 53:

			debug_output("[+] DNS reply caught (%s answers)" % pkt[DNS].ancount)
			
			for i in xrange(pkt[DNS].ancount): # cycle through responses and add records to graph
				#pkt[DNS].show()

				if pkt[DNS].an[i].type != 1:
					debug_output('No A records in reply')
					continue

				hname = pkt[DNS].an[i].rrname
				ipaddr = pkt[DNS].an[i].rdata

				# check if hname ends with '.'

				if hname[-1:] == ".":
					hname = hname[:-1]
				
				_hname = self.analytics.add_text([hname], ['sniffer', self.name])
				_ipaddr = self.analytics.add_text([ipaddr], ['sniffer', self.name])

				debug_output("Added %s, %s" %(hname, ipaddr))

				debug_output("Response %s: %s -> %s" % (i, _hname, _ipaddr))

				if _hname and _ipaddr:

					if _hname['_id'] not in self.nodes_ids:
						self.nodes_ids.append(_hname['_id'])
						self.nodes.append(_hname)
						new_elts.append(_hname)

					if _ipaddr['_id'] not in self.nodes_ids:
						self.nodes_ids.append(_ipaddr['_id'])
						self.nodes.append(_ipaddr)
						new_elts.append(_ipaddr)

					if pkt[DNS].an[i].type == 1: # A record
						type = "A"
					else:
						type = "?"

					#conn = self.analytics.data.connect(_hname, _ipaddr, type, True)
					conn = {'attribs': type, 'src': _hname['_id'], 'dst': _ipaddr['_id'], '_id': { '$oid': str(_hname['_id'])+str(_ipaddr['_id'])}}
					if conn not in self.edges:
						self.edges.append(conn)
						new_edges.append(conn)

			# deal with the original request
			question = pkt[DNS].qd.qname
			_question = self.analytics.add_text([question], ['sniffer', self.name])

			if _question:
				if _question['_id'] not in self.nodes_ids:
						self.nodes_ids.append(_question['_id'])
						self.nodes.append(_question)
						new_edges.append(_question)

				#conn = self.analytics.data.connect(_question, elt, "resolve", True)
				conn = {'attribs': type, 'src': _hname['_id'], 'dst': _ipaddr['_id'], '_id': { '$oid': str(_hname['_id'])+str(_ipaddr['_id'])}}
				if conn not in self.edges:
						self.edges.append(conn)
						new_edges.append(conn)

		return new_elts, new_edges
		
	def handlePacket(self, pkt):
		elts = []
		edges = []

		print pkt.summary()

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

		self.send_nodes(elts, edges)


	def send_nodes(self, elts=[], edges=[]):

		debug_output('New stuff:\nNodes: %s\nEdges:%s' % (", ".join(["%s: %s" % (e['type'], e['value']) for e in elts]), len(edges)))

		#data = { 'query': {}, 'nodes':self.nodes, 'edges': self.edges }
		data = { 'querya': {}, 'nodes':elts, 'edges': edges }
		try:
			if len(elts) > 0 or len(edges) > 0:
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