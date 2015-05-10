import pwd, os, sys, time, threading, datetime

from scapy.all import *
from scapy.error import Scapy_Exception
from bson.json_util import dumps as bson_dumps
from bson.json_util import loads as bson_loads
from bson.objectid import ObjectId

from Malcom.sniffer.flow import Flow
from Malcom.auxiliary.toolbox import debug_output
from Malcom.sniffer.messenger import SnifferMessenger
from Malcom.sniffer.tlsproxy.tlsproxy import MalcomTLSProxy
from Malcom.model.model import Model

try:
	import yara
	has_yara = True
	# load_yara_rules
except Exception, e:
	debug_output("yara-python was not found on system. Please install yara if you want to use your rules.", type='error')
	has_yara = False


types = ['hostname', 'ip', 'url', 'as', 'malware']
rr_codes = { 1: "A", 28: "AAAA", 2: "NS", 5: "CNAME", 15: "MX", 255: 'ANY', 12: "PTR" }
known_tcp_ports = {'80':'HTTP', '443':'HTTPS', '21':'FTP', '22':'SSH'}
known_udp_ports = {'53':'DNS'}
NOTROOT = "nobody"

class SnifferEngine(object):
	"""docstring for SnifferEngine"""

	def __init__(self, setup, yara_rules=None):
		super(SnifferEngine, self).__init__()
		self.setup = setup
		sys.stderr.write("[+] Starting sniffer...\n")

		# check if sniffer directory exists
		if not os.path.isdir(self.setup['SNIFFER_DIR']):
			sys.stderr.write("Could not load directory specified in sniffer_dir: %s\n" % self.setup['SNIFFER_DIR'])
			exit()

		sys.stderr.write("[+] Successfully loaded sniffer directory: %s\n" % self.setup['SNIFFER_DIR'])

		if setup['TLS_PROXY_PORT'] > 0:
			from Malcom.sniffer.tlsproxy.tlsproxy import MalcomTLSProxy
			sys.stderr.write("[+] Starting TLS proxy on port %s\n" % setup['TLS_PROXY_PORT'])
			self.tls_proxy = MalcomTLSProxy(setup['TLS_PROXY_PORT'])
			self.tls_proxy.engine = self
			self.tls_proxy.start()
		else:
			self.tls_proxy = None

		self.sessions = {}

		self.model = Model(self.setup)
		self.db_lock = threading.Lock()

		self.messenger = SnifferMessenger()
		self.messenger.snifferengine = self


		# debug_output("Importing packet captures...")

		# for s in self.model.get_sniffer_sessions():
		# 	self.sessions[s['name']] = SnifferSession(	s['name'],
		# 												None,
		# 												None,
		# 												self,
		# 												filter_restore=s['filter'],
		# 												intercept_tls=s['intercept_tls'] if setup['TLS_PROXY_PORT'] else False)
		# 	self.sessions[s['name']].pcap = True

		if has_yara and yara_rules:
			try:
				self.yara_rules = self.load_yara_rules(yara_rules)
			except Exception, e:
				sys.stderr.write("Could not load yara rules specified in yara_path: %s\n" % e)
				exit()


		else:
			self.yara_rules = None


	def load_yara_rules(self, path):
		debug_output("Compiling YARA rules from %s" % path)
		if path[-1] != '/':	path += '/' # add trailing slash if not present
		filepaths = {}
		for file in os.listdir(path):
			if file.endswith('.yar'):
				print file
				filepaths[file] = path + file
		debug_output("Loaded %s YARA rule files in %s" % (len(filepaths), path))
		return yara.compile(filepaths=filepaths)

	def fetch_sniffer_session(self, session_id):
		try:
			debug_output("Fetching session %s from memory" % session_id)
			session = self.sessions.get(ObjectId(session_id))
		except Exception as e:
			debug_output("An {} error occurred when fetching session '{}': {}".format(type(e).__name__, session_id, e), 'error')
			return

		# if not found, recreate it from the DB
		if not session:
			debug_output("Fetching session %s from DB" % session_id)
			s = self.model.get_sniffer_session(session_id)
			if not s:
				return None
			# TLS interception only possible if PCAP hasn't been generated yet
			intercept_tls = s['intercept_tls'] and not s['pcap']

			if s:
				session = SnifferSession(	s['name'],
											None,
											None,
											self,
											id=s['_id'],
											filter_restore=s['filter'],
											intercept_tls=intercept_tls)
				session.pcap = s['pcap']
				session.public = s['public']
				session.date_created = s['date_created']
				self.sessions[session.id] = session
				session_data = bson_loads(s['session_data'])
				session.nodes = session_data['nodes']
				session.edges = session_data['edges']
				session.packet_count = s['packet_count']
				session.flows = {}
				for flow in session_data['flows']:
					f = Flow.load_flow(flow)
					session.flows[f.fid] = f

		return session


	def new_session(self, params):
		session_name = params['session_name']
		remote_addr = params['remote_addr']
		filter = params['filter']
		intercept_tls = params['intercept_tls']

		sniffer_session = SnifferSession(session_name, remote_addr, filter, self, None, intercept_tls)
		sniffer_session.pcap = params['pcap']
		sniffer_session.public = params['public']

		return self.model.save_sniffer_session(sniffer_session)

	def delete_session(self, session_id):
		session = self.fetch_sniffer_session(session_id)

		if not session:
			return 'notfound'

		if session.status():
			return "running" # session running

		else:
			self.model.del_sniffer_session(session, self.setup['SNIFFER_DIR'])
			return "removed"

	def commit_to_db(self, session):
		with self.db_lock:
			session.save_pcap()
			self.model.save_sniffer_session(session)
		debug_output("[+] Sniffing session %s saved" % session.name)
		return True


class SnifferSession():

	def __init__(self, name, remote_addr, filter, engine, id=None, intercept_tls=False, ws=None, filter_restore=None):
		self.id = id
		self.engine = engine
		self.model = engine.model
		self.date_created = datetime.datetime.utcnow()
		self.name = name
		self.ws = ws
		self.ifaces = self.engine.setup['IFACES']
		filter_ifaces = ""
		for i in self.ifaces:
			if self.ifaces[i] == "Not defined": continue
			filter_ifaces += " and not host %s " % self.ifaces[i]
		self.filter = "ip and not host 127.0.0.1 and not host %s %s" % (remote_addr, filter_ifaces)
		# self.filter = "ip and not host 127.0.0.1 and not host %s" % (remote_addr)
		if filter != "":
			self.filter += " and (%s)" % filter
		self.stopSniffing = False

		if filter_restore:
			self.filter = filter_restore

		self.thread = None
		self.thread_active = False
		self.pcap = False
		self.pcap_filename = "%s-%s.pcap" % (self.id, self.name) # TODO CHANGE THIS AND MAKE IT SECURE
		self.pkts = []
		self.packet_count = 0

		self.nodes = {}
		self.edges = {}

		# flows
		self.flows = {}

		self.intercept_tls = intercept_tls
		if self.intercept_tls:
			debug_output("[+] Intercepting TLS")
			self.tls_proxy = self.engine.tls_proxy
			# self.tls_proxy.add_flows(self.flows)
		else:
			debug_output("[-] No TLS interception")

	def get_nodes(self):
		return [str(self.nodes[n]['_id']) for n in self.nodes]

	def load_pcap(self):
		filename = self.pcap_filename
		debug_output("Loading PCAP from %s " % filename)
		self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1, offline=self.engine.setup['SNIFFER_DIR']+"/"+filename)
		debug_output("Loaded %s packets from file." % len(self.pkts))
		return True

	def start(self):
		self.thread = threading.Thread(target=self.run)
		self.thread.start()

	def reset_session_progress(self):
		self.packet_count = 0
		self.nodes = {}
		self.edges = {}
		self.flows = {}

	def run(self):
		self.thread_active = True

		self.reset_session_progress()
		debug_output("[+] Sniffing session %s started" % self.name)
		debug_output("[+] Filter: %s" % self.filter)
		self.stopSniffing = False

		if self.pcap:
			self.load_pcap()
		else:
			self.sniff(stopper=self.stop_sniffing, filter=self.filter, prn=self.handlePacket, stopperTimeout=1, store=0)

		debug_output("[+] Sniffing session %s stopped" % self.name)
		self.engine.commit_to_db(self)

		data = {'type': 'sniffdone', 'session_name':self.name}
		self.engine.messenger.broadcast(bson_dumps(data), 'sniffer-data', 'sniffdone')

		self.thread_active = False
		return

	def update_nodes(self):
		return { 'query': {}, 'nodes': self.nodes, 'edges': self.edges }

	def flow_status(self, include_payload=False, encoding='raw'):
		data = {}
		data['flows'] = []
		for fid in self.flows:
			data['flows'].append(self.flows[fid].get_statistics(self.engine.yara_rules, include_payload, encoding))
		data['flows'] = sorted(data['flows'], key= lambda x: x['timestamp'])
		return data

	def stop(self):
		self.stopSniffing = True
		if self.thread:
			self.thread.join()
		return True

	def status(self):
		return self.thread_active

	def save_pcap(self):
		if self.packet_count > 0 and not self.pcap:
			debug_output("Generating PCAP for %s (length: %s)" % (self.name, len(self.pkts)))
			filename = self.engine.setup['SNIFFER_DIR'] + "/" + self.pcap_filename
			wrpcap(filename, self.pkts)
			self.pcap = True

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

			if ip not in self.nodes:

				ip = self.model.add_text([ip], ['sniffer', self.name])

				if ip == []: continue # tonight is not the night to add ipv6 support

				# do some live analysis
				new = ip.analytics()
				for n in new:
					saved = self.model.save(n[1])

					self.nodes[str(saved['value'])] = saved
					new_elts.append(saved)

					# Do the link. The link should be kept because it is not
					# exclusively related to this sniffing sesison
					conn = self.model.connect(ip, saved, n[0])
					if conn['_id'] not in self.edges:
						self.edges[str(conn['_id'])] = conn
						new_edges.append(conn)

				self.nodes[ip['value']] = ip
				new_elts.append(ip)
			else:
				ip = self.nodes[ip]
				new_elts.append(ip)

			ids.append(ip['_id']) # collect the ID of both IPs to create a connection afterwards

		# Temporary "connection". IPs are only connceted because hey are communicating with each other
		oid = "$oid"

		if TCP in pkt:
			ports = known_tcp_ports
			attribs = "TCP"
		elif UDP in pkt:
			ports = known_udp_ports
			attribs = "UDP"

		attribs = ports.get(str(dest['port']), attribs)
		if attribs in ["TCP", "UDP"]:
			attribs = ports.get(str(source['port']), attribs)

		conn = {'attribs': attribs, 'src': ids[0], 'dst': ids[1], '_id': { oid: str(ids[0])[12:]+str(ids[1])[12:]}}

		self.edges[str(conn['_id'])] = conn

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

			if question not in self.nodes:

				_question = self.model.add_text([question], ['sniffer', self.name]) # log it to db (for further reference)

				if _question:
					debug_output("Caught DNS question: %s" % (_question['value']))

					self.nodes[_question['value']] = _question
					new_elts.append(_question)

			else:
				_question = self.nodes[_question['value']] # [e for e in self.nodes if e['value'] == question][0]
				new_elts.append(_question)

			response_types = [pkt[DNS].an, pkt[DNS].ns, pkt[DNS].ar]
			response_counts = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]

			for i, response in enumerate(response_types):
				if response_counts[i] == 0: continue

				debug_output("[+] DNS replies caught (%s answers)" % response_counts[i])

				for rr in xrange(response_counts[i]):
					if response[rr].type not in [1, 2, 5, 15]:
						debug_output('No relevant records in reply')
						continue

					rr = response[rr]

					rrname = rr.rrname
					rdata = rr.rdata

					# check if rrname ends with '.'
					if rrname[-1:] == ".":
						rrname = rrname[:-1]

					# check if we haven't seen these already
					if rrname not in self.nodes:
						_rrname = self.model.add_text([rrname], ['sniffer', self.name]) # log every discovery to db

						if _rrname != []:
							self.nodes[_rrname['value']] = _rrname
							new_elts.append(_rrname)
					else:
						_rrname = self.nodes[rrname] # [e for e in self.nodes if e['value'] == rrname][0]
						new_elts.append(_rrname)

					if rdata not in self.nodes:
						_rdata = self.model.add_text([rdata], ['sniffer', self.name]) # log every discovery to db
						if _rdata != []: # avoid linking elements if only one is found
							self.nodes[_rdata['value']] = _rdata
							new_elts.append(_rdata)

							# do some live analysis
							# new = _rdata.analytics()
							# for n in new:
							# 	saved = self.analytics.save_element(n[1])
							# 	self.nodes_ids.append(saved['_id'])
							# 	self.nodes_values.append(saved['value'])
							# 	self.nodes.append(saved)
							# 	new_elts.append(saved)

							# 	#do the link
							# 	conn = self.analytics.data.connect(_rdata, saved, n[0])
							# 	if conn not in self.edges:
							# 		self.edges.append(conn)
							# 		new_edges.append(conn)
					else:
						_rdata = self.nodes[rdata] #[e for e in self.nodes if e['value'] == rdata][0]
						new_elts.append(_rdata)

					# we can use a real connection here
					# conn = {'attribs': 'A', 'src': _rrname['_id'], 'dst': _rdata['_id'], '_id': { '$oid': str(_rrname['_id'])+str(_rdata['_id'])}}

					# if two elements are found, link them
					if _rrname != [] and _rdata != []:
						debug_output("Caught DNS answer: %s -> %s" % ( _rrname['value'], _rdata['value']))
						debug_output("Added %s, %s" %(rrname, rdata))
						conn = self.model.connect(_rrname, _rdata, rr_codes[rr.type], True)
						self.edges[str(conn['_id'])] = conn
						new_edges.append(conn)
					else:
						debug_output("Don't know what to do with '%s' and '%s'" % (_rrname, _rdata), 'error')

					# conn = self.analytics.data.connect(_question, elt, "resolve", True)
					# conn = {'attribs': 'query', 'src': _question['_id'], 'dst': _rdata['_id'], '_id': { '$oid': str(_rrname['_id'])+str(_rdata['_id']) } }
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
			url = self.model.add_text([http_elts['url']])
			if url:
				if url['value'] not in self.nodes:
					self.nodes[url['value']] = url
					new_elts.append(url)

			host = self.model.add_text([http_elts['host']])
			if host:
				if host['value'] not in self.nodes:
					self.nodes[host['value']] = host
					new_elts.append(host)

			# in this case, we can save the connection to the DB since it is not temporary
			#conn = {'attribs': http_elts['method'], 'src': host['_id'], 'dst': url['_id'], '_id': { '$oid': str(host['_id'])+str(url['_id'])}}
			if url and host:
				conn = self.model.connect(host, url, "host")
				self.edges[str(conn['_id'])] = conn
				new_edges.append(conn)

				src_addr = self.model.get(value=flow.src_addr)
				conn_http = {'attribs': http_elts['method'], 'src': src_addr['_id'], 'dst': host['_id'], '_id': { '$oid': str(src_addr['_id'])[12:]+str(host['_id'])[12:]}}
				self.edges[str(conn_http['_id'])] = conn_http
				new_edges.append(conn_http)

		return new_elts, new_edges

	def handlePacket(self, pkt):


		IP_layer = IP if IP in pkt else IPv6 # add IPv6 support another night...
		if IP_layer == IPv6: return

		self.pkts.append(pkt)
		self.packet_count += 1

		elts = []
		edges = []

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

		# STANDARD PACKET ANALYSIS - extract IP addresses and domain names
		# the magic for extracting elements from packets happens here

		new_elts, new_edges = self.checkIP(pkt) # pass decode information if found
		if new_elts:
			elts += new_elts
		if new_edges:
			edges += new_edges


		new_elts, new_edges = self.checkDNS(pkt)
		if new_elts:
			elts += new_elts
		if new_edges:
			edges += new_edges


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
			debug_output("TLS SYN: %s:%s -> %s:%s" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
			# this could actually be replaced by only flow
			self.tls_proxy.hosts[(pkt[IP].src, pkt[TCP].sport)] = (pkt[IP].dst, pkt[TCP].dport, flow.fid)
			self.tls_proxy.factory.flows[flow.fid] = flow


		if elts != [] or edges != []:
			self.send_nodes(elts, edges)
		if self.pcap:
			pass

	def send_flow_statistics(self, flow):
		data = {}
		data['flow'] = flow.get_statistics(self.engine.yara_rules)
		data['type'] = 'flow_statistics_update'
		data['session_name'] = self.name

		self.engine.messenger.broadcast(bson_dumps(data), 'sniffer-data', 'flow_statistics_update')

	def send_nodes(self, elts=[], edges=[]):

		for e in elts:
			e['fields'] = e.default_fields

		data = { 'querya': {}, 'nodes': elts, 'edges': edges, 'type': 'nodeupdate', 'session_name': self.name}
		try:
			if (len(elts) > 0 or len(edges) > 0):
				self.engine.messenger.broadcast(bson_dumps(data), 'sniffer-data', 'nodeupdate')
		except Exception, e:
			debug_output("Could not send nodes: %s" % e, 'error')

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
					if offline:
						time.sleep(0.05)
			except KeyboardInterrupt:
				break
		s.close()
		return plist.PacketList(lst,"Sniffed")
