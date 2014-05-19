from Malcom.shmem.SharedData import Messenger
from Malcom.auxiliary.toolbox import send_msg, debug_output
import json, time, redis, sys


class WebMessenger(Messenger):

	def __init__(self):
		super(WebMessenger, self).__init__()
		self.name = 'web'
		sys.stderr.write("[+] WebMessenger started\n")

		self.subscribe_channel('analytics', self.analytics_handler)
		self.subscribe_channel('sniffer-data', self.sniffer_data_handler)

		self.websocket_for_session = {}
		self.analytics_ws = None
		
	def analytics_handler(self, msg):
		msg = json.loads(msg)
		queryid = msg['queryid']
		src = msg['src']
		
		if msg.get('type', False) == 'analyticsUpdate':
			msg = msg['msg']
			try:
				send_msg(self.analytics_ws, msg, type='analyticsstatus')
			except Exception, e:
				print e
	
	def sniffer_data_handler(self, msg):
		msg = json.loads(msg)
		queryid = msg['queryid']
		src= msg['src']
		msg_type = msg.get('type', False)
		
		if msg_type == "nodeupdate":
			data = json.loads(msg['msg']) # data = {nodes, edges, session_name}
			session_name = data['session_name']
			try:
				send_msg(self.websocket_for_session[session_name], data, type=data['type'])
			except Exception, e:
				debug_output('Error sending node udpate: %s' % e, 'error')

		if msg_type == 'flow_statistics_update':
			data = json.loads(msg['msg']) # data = {flows, session_name}
			session_name = data['session_name']
			try:
				send_msg(self.websocket_for_session[session_name], data, type=data['type'])
			except Exception, e:
				debug_output('Error sending flow: %s' % e, 'error')


		




