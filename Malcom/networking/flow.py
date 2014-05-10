from scapy.all import *
from scapy.error import Scapy_Exception
import pwd, os, sys, time, threading, string
from bson.json_util import dumps, loads
from Malcom.model.datatypes import Url, Hostname, Ip
import Malcom.auxiliary.toolbox as toolbox

rr_codes = {1: "A", 28: "AAAA", 2: "NS", 5: "CNAME", 15: "MX", 255: 'ANY', 12: 'PTR'}
r_codes = {3: "Name error", 0: "OK"}
		

class Decoder(object):

	@staticmethod
	def decode_flow(flow):
		data = None
		
		data = Decoder.HTTP_response(flow.payload)
		if data: return data
		
		data = Decoder.HTTP_request(flow.payload)
		if data: return data
		
		if flow.tls:

			data = Decoder.HTTP_request(flow.cleartext_payload, secure=True)
			if data: return data

			data = Decoder.HTTP_response(flow.cleartext_payload)
			if data: return data

		data = Decoder.DNS_request(flow.payload)
		if data: return data

		data = Decoder.DNS_response(flow.payload)
		if data: return data

		return False


	@staticmethod
	def DNS_request(payload):
		data = {}

		try: # we're relying on scapy to parse raw data... this is probably not gonig to end well.
			dns = DNS(payload)
			if dns.ancount == 0 and dns.nscount == 0 and dns.arcount == 0 and dns.qdcount > 0: # looks like a DNS query
				data['flow_type'] = 'dns_query'
				data['request_type'] = rr_codes.get(dns.qd.qtype, "?")
				data['questions'] = [ (dns.qd[i].qname, dns.qd[i].qtype) for i in range(dns.qdcount)]
				data['info'] = "DNS query: %s" % (", ".join( "%s (%s)" % (q[0], rr_codes.get(q[1], "?")) for q in data['questions'] ))
		except Exception, e:
			return {}

		return data

	@staticmethod
	def DNS_response(payload):
		data = {}
		
		try:
			dns = DNS(payload)
			if dns.ancount > 0 or dns.nscount > 0 or dns.arcount > 0 : # looks like a DNS response
				try:
					data['answers'] = [ (dns.an[i].rrname, dns.an[i].rdata, dns.an[i].type) for i in range(dns.ancount)]	
				except IndexError, e:
					dns.display()
					raise e
				
				data['rcode'] = dns.rcode
				data['flow_type'] = 'dns_response'
				if len(data['answers']) > 0:
					data['info'] = "DNS %s %s" % (r_codes[data['rcode']], ", ".join( "%s (%s) -> %s" % (q[0], rr_codes.get(q[2], "?"), q[1]) for q in data['answers'] ))
					if 'A' in [rr_codes.get(q[2]) for q in data['answers']] and r_codes[dns.rcode] == 'OK':
						data['flow_type'] = 'dns_response_OK'
				else:
					data['info'] = "DNS %s (no answers)" % r_codes[data['rcode']]
		except Exception, e:
			return {}

		return data


	@staticmethod
	def HTTP_request(payload, secure=False):
		data = {}
		request = re.search(r'(?P<method>GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT|PATCH) (?P<URI>\S*) HTTP', payload)
		if not request:
			return False
		else:
			data['method'] = request.group("method")
			data['uri'] = request.group('URI')
			host = re.search(r'Host: (?P<host>\S+)', payload)
			data['host'] = host.group('host') if host else "N/A"
			data['flow_type'] = "http_request"
			
			if secure:
				data['scheme'] = 'https://'
				data['type'] = 'HTTP request (TLS)'
			else:
				data['scheme'] = 'http://'
				data['type'] = 'HTTP request'

			data['url'] = data['scheme'] + data['host'] + data['uri']
			data['info'] = "%s request for %s" % (data['method'], data['url'])
			
			return data

	@staticmethod
	def HTTP_response(payload):
		data = {}
		response = re.search(r'(HTTP.* (?P<status_code>\d{3,3}))', payload)
		if not response:
			return False
		else:
			data['status'] = response.group("status_code")
			data['flow_type'] = 'http_response_%s' % data['status']
			encoding = re.search(r'Transfer-Encoding: (?P<encoding>\S+)', payload)
			data['encoding'] = encoding.group('encoding') if encoding else "N/A"
			response = re.search(r'\r\n\r\n(?P<response>[\S\s]*)', payload)
			#data['response'] = response.group('response') if response else "N/A"

			data['type'] = 'HTTP response'
			data['info'] = 'Status: %s' % (data['status'])
			
			# # chunk_encoding
			# try:
			# 	if response and encoding:
			# 		if data['encoding'] == 'chunked':
			# 			decoded = ""
			# 			encoded = data['response']
			# 			cursor = 0
			# 			chunk_size = -1
			# 			while chunk_size != 0:
			# 				chunk_size = int(encoded[cursor:cursor+encoded[cursor:].find('\r\n')], 16)
			# 				cursor += encoded[cursor:].find('\r\n') + 2
			# 				decoded += encoded[cursor:chunk_size+cursor]
			# 				cursor += chunk_size + 2
			# 			data['response'] = decoded
						
			# except Exception, e:
			# 	toolbox.debug_output("Could not decode chunked HTTP response: %s" % e, "error")
			
			return data
	

class Flow(object):
	"""docstring for Flow"""
	
	@staticmethod
	def flowid(pkt):
		IP_layer = IP if IP in pkt else IPv6
		fid = "flowid--%s-%s--%s-%s" % (pkt[IP_layer].src, pkt[IP_layer].sport, pkt[IP_layer].dst, pkt[IP_layer].dport)
		return fid.replace('.','-')

	@staticmethod
	def pkt_handler(pkt, flows):
		if IP not in pkt:
			return

		flowid = Flow.flowid(pkt)
		if flowid not in flows:
			flows[flowid] = Flow(pkt)
		else:
			flows[flowid].add_pkt(pkt)

	def reverse_flowid(self):
		fid = "flowid--%s-%s--%s-%s" % (self.dst_addr, self.dst_port, self.src_addr, self.src_port)
		return fid.replace('.','-')		

	def __init__(self, pkt):
		self.packets = []
		self.tls = False # until proven otherwise
		self.cleartext_payload = ""

		# set initial timestamp
		self.timestamp = pkt.time

		# addresses
		self.src_addr = pkt[IP].src 
		self.dst_addr = pkt[IP].dst

		self.src_port = pkt[IP].sport
		self.dst_port = pkt[IP].dport
	
		if pkt.getlayer(IP).proto == 6:
			self.protocol = 'TCP'
			self.buffer = [] # buffer for out-of-order packets
		elif pkt.getlayer(IP).proto == 17:
			self.protocol = 'UDP'
		else:
			self.protocol = "???"

		# see if we need to reconstruct flow (i.e. check SEQ numbers)
		self.payload = ""
		self.decoded_flow = None
		self.data_transfered = 0
		self.packet_count = 0
		self.fid = Flow.flowid(pkt)


		self.add_pkt(pkt)

		

	def extract_elements(self):
		if self.decoded_flow and self.decoded_flow['flow_type'] == 'http_request':
			return {'url': self.decoded_flow['url'], 'host': self.decoded_flow['host'], 'method': self.decoded_flow['method']}
		else:
			return None
	
	def add_pkt(self, pkt):
		self.packet_count += 1
		if self.protocol == 'TCP' and not self.tls:
			self.reconstruct_flow(pkt)
		elif self.protocol == 'UDP':
			self.packets += pkt
			self.payload += str(pkt[UDP].payload)
			self.data_transfered += len(self.payload)
		else:
			self.packets += pkt


	def reconstruct_flow(self, pkt):
		assert TCP in pkt

		# deal with all packets or only new connections ?

		if pkt[TCP].flags & 0x02:			# SYN flag detected
			self.seq = pkt[TCP].seq
			self.initial_seq = pkt[TCP].seq

			if Raw in pkt:
				self.payload += pkt[Raw].load
				self.data_transfered += len(pkt[Raw].load)

			self.packets += pkt
			self.seq += 1

		elif len(self.packets) > 0:
			self.buffer += pkt
			while self.check_buffer():
				pass

	def check_buffer(self):
		for i, pkt in enumerate(self.buffer):
			last = self.packets[-1:][0]
			
			# calculate expected seq
			if Raw in last:
				next_seq = self.seq + len(last[Raw].load)
			else:
				next_seq = self.seq
			
			# the packet's sequence number matches
			if next_seq == pkt[TCP].seq:
				
				# pop from buffer
				self.packets += self.buffer.pop(i)
				self.seq = pkt[TCP].seq

				if Raw in pkt:
					self.payload += str(pkt[Raw].load)
					self.data_transfered += len(pkt[Raw].load)
				
				return True

		return False

	def get_statistics(self):

		update = {
				'timestamp': self.timestamp,
				'fid' : self.fid,
				'src_addr': self.src_addr,
				'src_port': self.src_port,
				'dst_addr': self.dst_addr, 
				'dst_port': self.dst_port, 
				'protocol': self.protocol,
				'packet_count': self.packet_count,
				'data_transfered': self.data_transfered,
				'tls': self.tls,
				}

		# we'll use the type and info fields
		self.decoded_flow = Decoder.decode_flow(self)
		update['decoded_flow'] = self.decoded_flow

		return update

	def get_payload(self, encoding='web'):

		if self.tls:
			payload = self.cleartext_payload
		else:
			payload = self.payload

		if encoding == 'web':
			return unicode(payload, errors='replace')
		if encoding == 'raw':
			return payload
			

	def print_statistics(self):
		print "%s:%s  ->  %s:%s (%s, %s packets, %s buff)" % (self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.protocol, len(self.packets), len(self.buffer))



if __name__ == '__main__':
	
	filename = sys.argv[1]
	flows = {}
	sniff(prn=lambda x: Flow.pkt_handler(x, flows), offline=filename, store=0)

	for fid in flows:
		flows[fid].print_statistics()




