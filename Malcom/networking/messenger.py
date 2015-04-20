import json, threading, time, sys
from bson import json_util
from bson.json_util import loads as bson_loads
from bson.json_util import dumps as bson_dumps

from Malcom.shmem.SharedData import Messenger
from Malcom.auxiliary.toolbox import debug_output

class SnifferMessenger(Messenger):
	"""docstring for SnifferMessenger"""
	def __init__(self):
		super(SnifferMessenger, self).__init__()
		self.name = 'sniffer'
		self.snifferengine = None
		self.subscribe_channel('sniffer-commands', self.command_handler)
		self.command_lock = threading.Lock()
		debug_output("[+] Sniffer Messenger started")

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
			_id = self.snifferengine.new_session(params)
			final_msg = bson_dumps(_id)

		if cmd == 'sessionlist':
			session_list = []
			user = params.get('user', None)
			page = params.get('page', 0)
			private = params.get('private', False)

			for session in self.snifferengine.model.get_sniffer_sessions(private=private, username=user, page=page):

				if session['_id'] in self.snifferengine.sessions:
					session = self.snifferengine.sessions[session['_id']]
					active = session.status()
					session = session.__dict__
				else:
					active = False
					session_data = bson_loads(session['session_data'])
					session['nodes'] = session_data['nodes']
					session['edges'] = session_data['edges']
					session['id'] = session['_id']

				session_list.append( {   	'id': str(session.get('id')),
											'date_created': session.get('date_created'),
											'name': session.get('name'),
											'packets': session.get('packet_count'),
											'nodes': len(session.get('nodes')),
											'edges': len(session.get('edges')),
											'status': "Running" if active else "Stopped",
											'public': session.get('public'),
										} )

			final_msg = bson_dumps(session_list)

		if params.get('session_id', False):

			session = self.snifferengine.fetch_sniffer_session(params['session_id'])

			if not session:
				final_msg = 'notfound'

			if session:

				if cmd == 'sessioninfo':

					final_msg = {
							'name' : session.name,
							'filter' : session.filter,
							'pcap' : session.pcap,
							'packet_count': session.packet_count,
							'pcap_filename': session.pcap_filename,
							'id' : str(session.id),
							'public': session.public,
							'status': session.status(),
							'node_list': session.get_nodes(),
					}

				if cmd == 'sniffstatus':
					final_msg = {'status': session.status()}

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
					result = self.snifferengine.delete_session(params['session_id'])
					final_msg = result

				if cmd == 'sniffpcap':
					result = self.snifferengine.commit_to_db(session)
					final_msg = result

		if final_msg != None:
			reply = {'msg': final_msg, 'queryid': queryid, 'dst': src, 'src':self.name}
			self.publish_to_channel('sniffer-commands', json.dumps(reply))
		self.command_lock.release()

		return
