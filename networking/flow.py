from scapy.all import *
from scapy.error import Scapy_Exception
import pwd, os, sys, time, threading, string
from bson.json_util import dumps


class Decoder(object):

	@staticmethod
	def decode_flow(flow):
		data = None
		if flow.src_port == 80: # probable HTTP response
			data = Decoder.HTTP_response(flow.payload)
		if flow.dst_port == 80: # probable HTTP request
			data = Decoder.HTTP_request(flow.payload)

		if data:
			return data
		else:
			return False

	@staticmethod
	def HTTP_request(payload):
		data = {}
		request = re.search(r'(?P<method>GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT|PATCH) (?P<URI>\S*) HTTP', payload)
		if not request:
			return False

		else:
			data['method'] = request.group("method")
			data['uri'] = request.group('URI')
			host = re.search(r'Host: (?P<host>\S+)', payload)
			data['host'] = host.group('host') if host else "N/A"

			data['type'] = 'HTTP request'
			data['info'] = "%s request for %s" % (data['method'], data['host']+data['uri'])
			return data

	@staticmethod
	def HTTP_response(payload):
		data = {}
		response = re.search(r'(HTTP.* (?P<status_code>\d{3,3}))', payload)
		if not response:
			return False

		else:

			data['status'] = response.group("status_code")
			encoding = re.search(r'Transfer-Encoding: (?P<encoding>\S+)', payload)
			data['encoding'] = encoding.group('encoding') if encoding else "N/A"
			response = re.search(r'\r\n\r\n(?P<response>[\S\s]*)', payload)
			data['response'] = response.group('response') if response else "N/A"

			data['type'] = 'HTTP response'
			data['info'] = 'Status: %s' % (data['status'])
			try:
				if response and encoding:
					if data['encoding'] == 'chunked':
						decoded = ""
						encoded = data['response']
						cursor = 0
						chunk_size = -1
						while chunk_size != 0:
							chunk_size = int(encoded[cursor:cursor+encoded[cursor:].find('\r\n')], 16)
							cursor += encoded[cursor:].find('\r\n') + 2
							decoded += encoded[cursor:chunk_size+cursor]
							cursor += chunk_size + 2
						data['decoded_payload'] = decoded
			except Exception, e:
				return False
			

			return data
	

class Flow(object):
	"""docstring for Flow"""
	
	@staticmethod
	def flowid(pkt):
		fid = "flowid-%s-%s-%s-%s" % (pkt[IP].src, pkt[IP].sport, pkt[IP].dst, pkt[IP].dport)
		return fid.replace('.','-')

	@staticmethod
	def pkt_handler(pkt, flows):

		flowid = Flow.flowid(pkt)
		if flowid not in flows:
			flows[flowid] = Flow(pkt)
		else:
			flows[flowid].add_pkt(pkt)

	def __init__(self, pkt):
		self.packets = []

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
		self.data_transfered = 0
		self.packet_count = 0
		self.add_pkt(pkt)
		self.fid = Flow.flowid(pkt)
		
	
	def add_pkt(self, pkt):
		self.packet_count += 1
		if self.protocol == 'TCP':
			self.reconstruct_flow(pkt)
		else:
			self.packets += pkt


	def reconstruct_flow(self, pkt):
		assert TCP in pkt

		# deal with all packets or only new connections ?
		# if len(self.packets) == 0: # we're dealing with a new flow (maybe partial)

		if pkt[TCP].flags & 0x02:			# SYN flag detected
			self.seq = pkt[TCP].seq
			self.initial_seq = pkt[TCP].seq

			# in a perfect world, everyone respects RFCs
			if Raw in pkt:
				print "Data contained in SYN packet!"
				self.payload += pkt[Raw].load
				self.data_transfered += len(pkt[Raw].load)

			self.packets += pkt
			self.seq += 1

		elif len(self.packets) > 0:
			self.buffer += pkt
			while self.check_buffer():
				pass

	#def check_buffer(self, pkt):
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
				'fid' : self.fid,
				'src_addr': self.src_addr,
				'src_port': self.src_port,
				'dst_addr': self.dst_addr, 
				'dst_port': self.dst_port, 
				'protocol': self.protocol,
				'packet_count': self.packet_count,
				'data_transfered': self.data_transfered,
				#'decoded_protocol': self.decoded_protocol,
				}

		# we'll use the type and info fields
		update['decoded_flow'] = Decoder.decode_flow(self)


		return update

	def print_statistics(self):
		print "%s:%s  ->  %s:%s (%s, %s packets, %s buff)" % (self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.protocol, len(self.packets), len(self.buffer))



if __name__ == '__main__':
	
	filename = sys.argv[1]
	flows = {}
	sniff(prn=lambda x: Flow.pkt_handler(x, flows), offline=filename, store=0)

	for fid in flows:
		flows[fid].print_statistics()




