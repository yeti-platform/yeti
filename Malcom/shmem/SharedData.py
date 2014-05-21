from bson import json_util
import redis, threading, time, json, sys
import random
from Malcom.auxiliary.toolbox import debug_output

# analytics

class Messenger(object):
	"""docstring for RedisSubscriber"""
	def __init__(self):
		pass
		# super(Messenger, self).__init__()
		self.r = redis.StrictRedis(host='localhost', port=6379, db=0)

	def subscribe_channel(self, channel, callback):
		sys.stderr.write("[+] Subscribing to %s\n" % channel)
		t = threading.Thread(target=self.__listen_on_channel, args=(channel, callback))
		t.setDaemon(True)
		t.start()
		return t
	
	def __listen_on_channel(self, channel, callback):
		r = redis.StrictRedis(host='localhost', port=6379, db=0)
		client = r.pubsub()
		client.subscribe(channel)
		for item in client.listen():
			if item['type'] == 'message':
				# print "received [%s] %s" % (channel, item['data'])
				callback(item['data'])

	def publish_to_channel(self, channel, message):
		try:
			self.r.publish(channel, message)
		except Exception, e:
			debug_output("Could not broadcast: %s %s" % (e, message), 'error')
		

	def broadcast(self, msg, channel, type="bcast"):
		queryid = str(random.random())

		message = json.dumps({'msg': msg, 'queryid': queryid, 'src': self.name, 'type':type})
		try:
			# print "broadcast [%s] : %s" % (channel, type)
			self.r.publish(channel, message)
		except Exception, e:
			debug_output("Could not broadcast: %s %s" % (e, message), 'error')
		
		# self.client.subscribe(channel)
		#print "[%s] Sending %s message" % (msg, self.name)

	def send_recieve(self, msg, channel, params={}):
		queryid = str(random.random())
		message = json.dumps({'msg': msg, 'queryid': queryid, 'src': self.name, 'params': params})
		
		r = redis.StrictRedis(host='localhost', port=6379, db=0)
		p = r.pubsub()
		p.subscribe(channel)
		#print "[%s] Sending %s message" % (msg, self.name)
		messages = p.listen()
		r.publish(channel, message)

		while True:	
			#print "[%s] Waiting for response" % self.name
			message = messages.next()
			if message['type'] == 'message':
				#print "[%s] %s" % (self.name, message)
				data = json.loads(message['data'])
				if data.get('dst', "") == self.name and data['queryid'] == queryid:
					#print "[%s] Got message! (%s)" % (self.name, data['msg'])
					p.close()
					return data['msg']
			time.sleep(0.001)

if __name__ == '__main__':

	def printmsg(msg):
		print msg

	m = Messenger()
	m.subscribe_channel('test_chan', printmsg)

	a = ""
	while a != "quit":
		a = raw_input(">> ")
		m.publish_to_channel('test_chan', a)

	print "Quitting..."