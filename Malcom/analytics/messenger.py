import json, threading, time, sys

from Malcom.shmem.SharedData import Messenger
from Malcom.auxiliary.toolbox import debug_output


class AnalyticsMessenger(Messenger):
	"""docstring for AnalyticsMessenger"""
	def __init__(self, analytics_instance):
		super(AnalyticsMessenger, self).__init__()
		self.name = 'analytics'
		self.analytics_instance = analytics_instance
		self.subscribe_channel('analytics', self.message_handler)
		#self.status_update()
		debug_output("[+] Analytics Messenger started")

	def status_update(self):
		t = threading.Thread(target=self.__status_update)
		t.setDaemon(True)
		t.start()

	def __status_update(self):
		was_active = False
		while True:
			if self.analytics_instance.active:
				was_active = True
				msg = "Active (%s)" % self.analytics_instance.progress
				self.broadcast(msg, 'analytics', 'analyticsUpdate')
			
			if was_active and not self.analytics_instance.active:
				self.broadcast("Inactive", 'analytics', 'analyticsUpdate')
				was_active = False
			
			time.sleep(0.2)
		
	def message_handler(self, msg):
		msg = json.loads(msg)
		queryid = msg['queryid']
		src = msg['src']
		msg = msg['msg']
		
		if msg == 'statusQuery':
			ans = "Active" if self.analytics_instance.active else "Inactive"
			reply = {'msg': ans, 'queryid': queryid, 'dst': src, 'src':self.name}
			self.publish_to_channel('analytics', json.dumps(reply))

		if msg == 'progressQuery':
			reply = {'msg': self.analytics_instance.progress, 'queryid': queryid, 'dst': src, 'src':self.name}
			self.publish_to_channel('analytics', json.dumps(reply))

		return


	
