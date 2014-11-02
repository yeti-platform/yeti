from Malcom.shmem.SharedData import Messenger
from Malcom.auxiliary.toolbox import send_msg, debug_output
import json, time, redis, sys


class WebMessenger(Messenger):

	def __init__(self):
		super(WebMessenger, self).__init__()
		self.name = 'web'
		debug_output("[+] WebMessenger started")

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
		# print "webmsgr received", msg
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

		elif msg_type == 'flow_statistics_update':
			data = json.loads(msg['msg']) # data = {flows, session_name}
			session_name = data['session_name']
			try:
				send_msg(self.websocket_for_session[session_name], data, type=data['type'])
			except Exception, e:
				debug_output('Error sending flow data: %s' % e, 'error')

		elif msg_type == 'sniffdone':
			data = json.loads(msg['msg'])
			session_name = data['session_name']
			try:
				send_msg(self.websocket_for_session[session_name], data, type=data['type'])
			except Exception, e:
				debug_output('Error sending stop message: %s' % e, 'error')

		else:
			print msg
