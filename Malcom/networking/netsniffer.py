from scapy.all import *
from scapy.error import Scapy_Exception
import pwd, os, sys, time, threading
from bson.json_util import dumps

from bson.objectid import ObjectId


from Malcom.networking.flow import Flow
from Malcom.auxiliary.toolbox import debug_output
from Malcom.networking.tlsproxy.tlsproxy import MalcomTLSProxy
import Malcom

types = ['hostname', 'ip', 'url', 'as', 'malware']

NOTROOT = "nobody"


class Sniffer():

	def __init__(self, analytics, name, remote_addr, filter, ifaces, tls_proxy_port, ws=None):
		
		self.analytics = analytics
		self.name = name
		self.ws = ws
		self.ifaces = ifaces
		filter_ifaces = ""
		for i in ifaces:
			filter_ifaces += " and not host %s " % ifaces[i]
		self.filter = "ip and not host 127.0.0.1 and not host %s %s" % (remote_addr, filter_ifaces)

		if filter != "":
			self.filter += " and (%s)" % filter
		self.stopSniffing = False
		
		self.thread = None
		self.public = False
		self.pcap = False
		self.pkts = []

		# nodes, edges, their values, their IDs
		self.nodes = []
		self.edges = []
		self.nodes_ids = []
		self.nodes_values = []
		self.nodes_pk = []
		self.edges_ids = []

		# flows
		self.flows = {}
		
		# MalcomTLSProxy instance
		self.intercept_tls = True if tls_proxy_port else False
		self.tls_proxy_port = int(tls_proxy_port) if tls_proxy_port else None

		if self.intercept_tls:
			self.tls_proxy = Malcom.tls_proxy
			self.tls_proxy.add_flows(self.flows)
		else:
			debug_output("[-] No TLS interception")

	def load_pcap(self):
		debug_output("Loading PCAP from file...")
		timestamp = str(time.mktime(time.gmtime())).split('.')[0]
		filename = '/tmp/load-%s.cap' % timestamp

		f = open(filename, 'wb')
		f.write(self.pcap)
		f.close()
		self.pkts += self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1, offline=filename)	
		
		debug_output("Loaded %s packets from file." % len(self.pkts))

		self.pcap = False
		
		return True

	def run(self):
		debug_output("[+] Sniffing session %s started" % self.name)
		debug_output("[+] Filter: %s" % self.filter)
		self.stopSniffing = False
		
		if self.pcap:
			self.load_pcap()
		elif not self.public:
			self.pkts += self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1)	
		
		debug_output("[+] Sniffing session %s stopped" % self.name)

		return 

	def update_nodes(self):
		return { 'query': {}, 'nodes': self.nodes, 'edges': self.edges }

	def flow_status(self):
		data = {}
		data['flows'] = []
		for fid in self.flows:
			data['flows'].append(self.flows[fid].get_statistics())
		data['flows'] = sorted(data['flows'], key= lambda x: x['timestamp'])
		return data

	def start(self, remote_addr, public=False):
		self.public = public
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

		# get IP layer
		IP_layer = IP if IP in pkt else IPv6
		if IP_layer == IPv6: return None, None # tonight is not the night to add ipv6 support
	
		if IP_layer in pkt:	
			source['ip'] = pkt[IP_layer].src
			dest['ip'] = pkt[IP_layer].dst
		else: return None, None

		if TCP in pkt or UDP in pkt:
			source['port'] = pkt[IP_layer].sport
			dest['port'] = pkt[IP_layer].dport
		else: return None, None

		ips = [source['ip'], dest['ip']]
		ids = []
		
		for ip in ips:

			if ip not in self.nodes_values:
				ip = self.analytics.add_text([ip], ['sniffer', self.name])

				if ip == []: continue # tonight is not the night to add ipv6 support

				# do some live analysis
				new = ip.analytics()
				for n in new:
					saved = self.analytics.save_element(n[1])
					self.nodes_ids.append(saved['_id'])
					self.nodes_values.append(saved['value'])
					self.nodes.append(saved)
					new_elts.append(saved)
					
					#do the link
					conn = self.analytics.data.connect(ip, saved, n[0])
					if conn not in self.edges:
						self.edges.append(conn)
						new_edges.append(conn)

				
				self.nodes_ids.append(ip['_id'])
				self.nodes_values.append(ip['value'])
				self.nodes.append(ip)
				new_elts.append(ip)
			else:
				ip = [e for e in self.nodes if e['value'] == ip][0]

			ids.append(ip['_id'])


		# temporary "connection". IPs are only connceted because hey are communicating with each other
		oid = "$oid"
		conn = {'attribs': '%s > %s' %(source['port'], dest['port']), 'src': ids[0], 'dst': ids[1], '_id': { oid: str(ids[0])+str(ids[1])}}
		
		if conn not in self.edges:
			self.edges.append(conn)
			new_edges.append(conn)
		
		return new_elts, new_edges

	def checkDNS(self, pkt):
		new_elts = []
		new_edges = []

		# intercept DNS responses (these contain names and IPs)
		IP_layer = IP if IP in pkt else IPv6
		if DNS in pkt and pkt[IP_layer].sport == 53:

			#deal with the original DNS request
			question = pkt[DNS].qd.qname

			if question not in self.nodes_values:
				_question = self.analytics.add_text([question], ['sniffer', self.name]) # log it to db (for further reference)
				if _question:
					debug_output("Caught DNS question: %s" % (_question['value']))
					self.nodes_ids.append(_question['_id'])
					self.nodes_values.append(_question['value'])
					self.nodes.append(_question)
					new_elts.append(_question)

			else:
				_question = [e for e in self.nodes if e['value'] == question][0]

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
					
					# do some live analysis
					new = _ipaddr.analytics()
					for n in new:
						saved = self.analytics.save_element(n[1])
						self.nodes_ids.append(saved['_id'])
						self.nodes_values.append(saved['value'])
						self.nodes.append(saved)
						new_elts.append(saved)
						
						#do the link
						conn = self.analytics.data.connect(_ipaddr, saved, n[0])
						if conn not in self.edges:
							self.edges.append(conn)
							new_edges.append(conn)

					self.nodes_ids.append(_ipaddr['_id'])
					self.nodes_values.append(_ipaddr['value'])
					self.nodes.append(_ipaddr)
					new_elts.append(_ipaddr)
				else:
					_ipaddr = [e for e in self.nodes if e['value'] == ipaddr][0]

				debug_output("Caught DNS response %s: %s -> %s" % (i, _hname['value'], _ipaddr['value']))
				debug_output("Added %s, %s" %(hname, ipaddr))

				# we can use a real connection here
				# conn = {'attribs': 'A', 'src': _hname['_id'], 'dst': _ipaddr['_id'], '_id': { '$oid': str(_hname['_id'])+str(_ipaddr['_id'])}}
				conn = self.analytics.data.connect(_hname, _ipaddr, "A", True)
				if conn not in self.edges:
					self.edges.append(conn)
					new_edges.append(conn)

			

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
			#conn = {'attribs': http_elts['method'], 'src': host['_id'], 'dst': url['_id'], '_id': { '$oid': str(host['_id'])+str(url['_id'])}}
			conn = self.analytics.data.connect(host, url, "host")

			if conn not in self.edges:
				self.edges.append(conn)
				new_edges.append(conn)

		return new_elts, new_edges


	def handlePacket(self, pkt):

		IP_layer = IP if IP in pkt else IPv6 # add IPv6 support another night...
		if IP_layer == IPv6: return

		self.pkts.append(pkt)

		elts = []
		edges = []

		# STANDARD PACKET ANALYSIS - extract IP addresses and domain names
		# the magic for extracting elements from packets happens here

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

		
		# FLOW ANALYSIS - reconstruct TCP flow if possible
		# do flow analysis here, if necessary - this will be replaced by dpkt's magic

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

		
		# TLS MITM - intercept TLS communications and send cleartext to malcom
		# We want to be protocol agnostic (HTTPS, FTPS, ***S). For now, we choose which 
		# connections to intercept based on destination port number
		
		# We could also catch ALL connections and MITM only those which start with
		# a TLS handshake

		tlsports = [443]
		if TCP in pkt and pkt[TCP].flags & 0x02 and pkt[TCP].dport in tlsports and not self.pcap and self.intercept_tls: # of course, interception doesn't work with pcaps
			# mark flow as tls			
			flow.tls = True

			# add host / flow tuple to the TLS connection list
			debug_output("TLS SYN to from: %s:%s -> %s:%s" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
			# this could actually be replaced by only flow
			self.tls_proxy.hosts[(pkt[IP].src, pkt[TCP].sport)] = (pkt[IP].dst, pkt[TCP].dport, flow.fid) 

			
		if elts != [] or edges != []:
			self.send_nodes(elts, edges)
		if self.pcap:
			time.sleep(0.1)

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
		
		for e in elts:
			e['fields'] = e.display_fields

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