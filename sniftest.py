from scapy.all import *
import threading
import pwd, os, sys, time
from bson.json_util import dumps
import socket



types = ['hostname', 'ip', 'url', 'as', 'malware']

NOTROOT = "nobody"

# def sniff(i):
	
# 	nodes = [{ '_id': {'$oid' : i }, 'type': types[i%5], types[i%5]: types[i%5]}]
# 	data = { 'query': {}, 'nodes':nodes, 'edges': {} }

# 	return data



class Sniffer(threading.Thread):

	def __init__(self, websockets):
		threading.Thread.__init__(self)
		self.ws = websockets
		self.filter = "tcp port 80"
		self.keepSniffing = True

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
		#while 1:
		while self.keepSniffing:
			try:
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

		

	def run(self):
		
		print "[+] Sniffing started"
		#self.sniff(filter=self.filter, prn=self.handlePacket, store=0)	
		self.sniff(filter=self.filter, prn= lambda x: x.summary(), store=0)

		return 

	def printPkg(self, p):
		print p.summary

	def stopSniffing(self):
		print "[-] Stopping..."
		self.thread.join(1.0)
		
		if self.thread.isAlive():
		
			try:
				print "Attemptint to stop thread: %s" % self.thread.isAlive()
				thread._Thread__stop()
				print "Thread stopped: %s" % self.thread.isAlive()
			except:
				print(str(self.thread.getName()) + ' could not be terminated')
		print "[+] Sniffing stopped"

	def handlePacket(self, pkt):
		#print "pkt called"
		source = {}
		dest = {}
		if IP in pkt:
			source['ip'] = pkt[IP].src
			dest['ip'] = pkt[IP].dst

		if TCP or UDP in pkt:
			source['port'] = pkt[IP].sport
			dest['port'] = pkt[IP].dport

		#print str(source['ip'])+":"+str(source['port'])+" -> " + str(dest['ip'])+":"+str(dest['port'])

		self.send_to_websocket(str(dest['ip']))

	def send_to_websocket(self, elt):
		nodes = [{ '_id': {'$oid' : elt }, 'type': 'ip', 'ip': elt}]
		data = { 'query': {}, 'nodes':nodes, 'edges': {} }
		#print dumps(data)
		self.ws.send(dumps(data))
		


	
		

