#!/usr/bin/env python
# coding: utf-8
# inspired from http://musta.sh/2012-03-04/twisted-tcp-proxy.html
 
import sys, threading
from time import sleep
from collections import deque
 
from twisted.internet import defer, ssl
from twisted.internet import protocol
from twisted.internet import reactor
 
class ProxyClientProtocol(protocol.Protocol):
	"""This is the Protocol responsible for dealing with the end host, and forwarding back data to the proxy"""
	def connectionMade(self):
		self.cli_queue = self.factory.cli_queue
		self.cli_queue.get().addCallback(self.serverDataReceived)
 
	def serverDataReceived(self, chunk):
		if chunk is False:
			self.cli_queue = None
			self.factory.continueTrying = False
			self.transport.loseConnection()
		elif self.cli_queue:
			self.transport.write(chunk)
			self.cli_queue.get().addCallback(self.serverDataReceived)
		else:
			self.factory.cli_queue.put(chunk)
 
	def dataReceived(self, chunk):
		self.factory.srv_queue.put(chunk)
 
	def connectionLost(self, why):
		if self.cli_queue:
			self.cli_queue = None
 
 
class ProxyClientFactory(protocol.ReconnectingClientFactory):
	"""This is the Factory responsible for generating connection protocols towards the destination host"""
	maxDelay = 10
	continueTrying = True
	protocol = ProxyClientProtocol
 
	def __init__(self, srv_queue, cli_queue):
		self.srv_queue = srv_queue
		self.cli_queue = cli_queue

 
class ProxyServer(protocol.Protocol):
	"""This is the "server protocols" class, which will conncect to a remote host
	and forward data to and from both endpoints (i.e. proxy)"""
	def __init__(self):
		self.clientFactory = None
		self.client_payload = ""
		self.server_payload = ""
		
	def connectionMade(self):
		self.srv_queue = defer.DeferredQueue()
		self.cli_queue = defer.DeferredQueue()
		self.srv_queue.get().addCallback(self.clientDataReceived)

		src_addr = self.transport.getPeer().host
		src_port = self.transport.getPeer().port

		tuples = self.factory.hosts.get((src_addr, src_port), False)

		# check if we've got a new tuple to connect to and
		# if we're still waiting for connections or not
		while not tuples and self.factory.proxy.running: 
			sleep(0.1)
			tuples = self.factory.hosts.get((src_addr, src_port), False)

		if tuples:
			self.dst_addr, self.dst_port, dst_fid = tuples
			self.dst_flow = self.factory.flows[dst_fid]
			print "Connecting to %s:%s" % (self.dst_addr, self.dst_port)
		

 	# response from server - reverse flow
	def clientDataReceived(self, chunk):
		
		self.transport.write(chunk)
		self.srv_queue.get().addCallback(self.clientDataReceived)

		# these operations must be done after data is sent so that the flow is created
		self.src_flow = self.factory.flows[self.dst_flow.reverse_flowid()]
		self.server_payload += chunk

		self.src_flow.cleartext_payload = self.server_payload
		self.src_flow.data_transfered = len(self.server_payload)
		self.src_flow.tls = True



 	# data from client - original flow
	def dataReceived(self, chunk):
		self.client_payload += chunk

		# update flow
		self.dst_flow.cleartext_payload = self.client_payload
		self.dst_flow.data_transfered = len(self.client_payload)
		
		if self.clientFactory == None:
			self.clientFactory = ProxyClientFactory(self.srv_queue, self.cli_queue)
			reactor.connectSSL(self.dst_addr, self.dst_port, self.clientFactory, ssl.ClientContextFactory())
		
		self.cli_queue.put(chunk)
 
	def connectionLost(self, why):
		self.cli_queue.put(False)



class MalcomTLSFactory():
 	"""This is the Factory responsible for generating "server protocols" (instances of incoming connections)"""
 	def __init__(self, hosts):
 		self.hosts = hosts
 		self.protocols = []

 	def doStart(self):
 		pass

 	def buildProtocol(self, address):
 		p = self.protocol()
 		p.factory = self
 		self.protocols.append(p)
 		return p

 	def doStop(self):
 		for p in self.protocols:
 			p.transport.loseConnection()


class MalcomTLSProxy(threading.Thread):
	"""This class will handle the twisted reactor"""
	def __init__(self, flows, port=9999):
		super(MalcomTLSProxy, self).__init__()
		self.hosts = {}
		self.factory = MalcomTLSFactory(self.hosts)
		self.factory.proxy = self
		self.factory.flows = flows
		self.running = True
		self.thread = None
		self.port = port

	def run(self):
		self.factory.protocol = ProxyServer
		reactor.listenSSL(self.port, self.factory, ssl.DefaultOpenSSLContextFactory('Malcom/networking/tlsproxy/keys/server.key', 'Malcom/networking/tlsproxy/keys/server.crt'), interface="0.0.0.0")

		self.thread = threading.Thread(None, reactor.run, None, (), {'installSignalHandlers': 0})
		self.thread.start()

		try:
			while self.running:
				sleep(5)
		except KeyboardInterrupt, e:
			self.stop()
		
	def stop(self):
		self.running = False
		reactor.callFromThread(reactor.stop)
		self.thread.join()
 
if __name__ == "__main__":
	m = MalcomTLSProxy()
	m.run()
	







