from Malcom.shmem.SharedData import Messenger
import json, threading, time, sys
from bson import json_util

class SnifferMessenger(Messenger):
	"""docstring for SnifferMessenger"""
	def __init__(self):
		super(SnifferMessenger, self).__init__()
		self.name = 'sniffer'
		self.snifferengine = None
		self.subscribe_channel('sniffer-commands', self.command_handler)
		self.command_lock = threading.Lock()
		sys.stderr.write("[+] Sniffer Messenger started\n")

	def update_nodes(self, nodes, edges, session_name):
		msg = {'nodes':nodes, 'edges':edges, 'session_name': session_name}
		self.broadcast(msg, 'sniffer-data', 'nodeupdate')

	def command_handler(self, msg):
		self.command_lock.acquire()
		msg = json.loads(msg)
		cmd = msg['msg']
		params = msg.get('params', {})
		src = msg['src']
		queryid = msg['queryid']
		final_msg = None

		if cmd == 'newsession':
			self.snifferengine.new_session(params)
			final_msg = True

		if cmd == 'sessionlist':
			session_list = {}
			for session in self.snifferengine.sessions:
				session = self.snifferengine.sessions[session]
				
				session_list[session.name] = {  'name': session.name,
												'packets': session.packet_count,
												'nodes': len(session.nodes),
												'edges': len(session.edges),
												'status': "Running" if session.status() else "Stopped",
												}

			final_msg = session_list

		try:
			session = self.snifferengine.sessions[params.get('session_name')]
		except Exception, e:
			session = False

		if session:

			if cmd == 'sessioninfo':
				final_msg = {
						'name' : session.name,
						'filter' : session.filter,
						'pcap' : session.pcap
				}
	
			if cmd == 'sniffstatus':
				final_msg = session.status()

			if cmd == 'sniffupdate':
				# this needs to be stringyfied, or else encoding errors will ensue
				final_msg = session.update_nodes()
				final_msg = json.dumps(final_msg, default=json_util.default)

			if cmd == 'sniffstart':
				#self.snifferengine.start_session(params['session_name'], params['remote_addr'])
				session.start(params['remote_addr'])
				final_msg = True

			if cmd == 'sniffstop':
				session.stop()
				final_msg = True

			if cmd == 'flowstatus':
				flow = session.flow_status()
				# this needs to be stringyfied, or else encoding errors will ensue
				final_msg = flow

			if cmd == 'flow_statistics_update':
				print "Received 'flow_statistics_update' message. Please implement me? "

			if cmd == 'get_flow_payload':
				if params['flowid'] in session.flows:
					final_msg = session.flows[params['flowid']].get_payload(encoding='base64')
				else:
					final_msg = False


			if cmd == 'sniffdelete':
				result = self.snifferengine.delete_session(params['session_name'])
				final_msg = result

			if cmd == 'sniffpcap':
				result = session.generate_pcap()
				final_msg = result

		if final_msg != None:
			reply = {'msg': final_msg, 'queryid': queryid, 'dst': src, 'src':self.name}
			self.publish_to_channel('sniffer-commands', json.dumps(reply))
		self.command_lock.release()
		
		return

	

	
