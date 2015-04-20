from flask import Blueprint, render_template, abort, request, g
import gevent

from bson.objectid import ObjectId
from bson.json_util import dumps, loads

from Malcom.web.webserver import Model, login_required
from Malcom.auxiliary.toolbox import *



malcom_websockets = Blueprint('malcom_websockets', __name__)



# APIs (websockets) =========================================

@malcom_websockets.route('/analytics')
@login_required
def analytics_api():
	debug_output("Call to analytics API")

	if request.environ.get('wsgi.websocket'):
		debug_output("Got analytics websocket")

		ws = request.environ['wsgi.websocket']

		g.messenger.analytics_ws = ws

		while True:
			try:
				message = loads(ws.receive())
				debug_output("(analytics webAPI) Received: %s" % message)
			except Exception, e:
				return ""

			cmd = message['cmd']

			if cmd == 'analyticsstatus':
				while True:
					gevent.sleep(1)


@malcom_websockets.route('/sniffer/streaming/<session_name>')
@login_required
def sniffer_streaming_api(session_name):
	debug_output("Call to streaming API for session %s" % session_name)

	if request.environ.get('wsgi.websocket'):
		debug_output("Got websocket for session %s" % session_name)
		ws = request.environ['wsgi.websocket']
		g.messenger.websocket_for_session[session_name] = ws

		while True:
			gevent.sleep(1)


@malcom_websockets.route('/sniffer')
@login_required
def sniffer_api():
	debug_output("Call to sniffer API")

	if request.environ.get('wsgi.websocket'):

		ws = request.environ['wsgi.websocket']

		while True:
			try:
				msg = ws.receive()
				message = loads(msg)
			except Exception, e:
				debug_output("Could not decode JSON message: %s\n%s" % (e, msg) )
				return ""

			debug_output("(sniffer webAPI) Received: %s" % message)

			cmd = message['cmd']
			session_id = message['session_id']

			session = "fail"

			# websocket commands
			params = {'session_id': session_id}

			if cmd == 'sessionlist':
				session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
				# REDIS query sniffer for info
				# session_list = [s for s in Malcom.sniffer_sessions]
				send_msg(ws, {'session_list': session_list}, type=cmd)
				continue

			if cmd == 'sniffstart':
				params['remote_addr'] = str(request.remote_addr)
				msg = g.messenger.send_recieve('sniffstart', 'sniffer-commands', params=params)

				# REDIS send message to sniffer
				send_msg(ws, "OK", type=cmd)
				continue

			if cmd == 'sniffstop':
				msg = g.messenger.send_recieve('sniffstop', 'sniffer-commands', params=params)

				send_msg(ws, msg, type=cmd)
				# REDIS send message to sniffer
				# if session.status():
				# 	session.stop()
				# 	send_msg(ws, 'OK', type=cmd)
				# else:
				# 	send_msg(ws, 'Error: sniffer not running', type=cmd)
				continue

			if cmd == 'sniffstatus':
				status = g.messenger.send_recieve('sniffstatus', 'sniffer-commands', params=params)

				# REDIS send message to sniffer
				if status:
					status = 'active'
					debug_output("Session %s is active" % params['session_id'])
					send_msg(ws, {'status': 'active', 'session_id': params['session_id']}, type=cmd)
				else:
					status = 'inactive'
					debug_output("Session %s is inactive" % params['session_id'])
					send_msg(ws, {'status': 'inactive', 'session_id': params['session_id']}, type=cmd)
				continue

			if cmd == 'sniffupdate':
				# REDIS send message to sniffer
				msg = g.messenger.send_recieve('sniffupdate', 'sniffer-commands', params=params)
				data = json.loads(msg) # json loads so that it doesn't complain about fake object ids
				data['type'] = cmd
				if data:
					ws.send(dumps(data))
				continue

			if cmd == 'flowstatus':
				# REDIS send message to sniffer
				flow = g.messenger.send_recieve('flowstatus', 'sniffer-commands', params=params)

				data = flow # remember we had to stringify the data to have the right encoding
				data['type'] = cmd
				if data:
					ws.send(dumps(data))
				continue

			if cmd == 'get_flow_payload':
				params['flowid'] = message['flowid']
				payload = g.messenger.send_recieve('get_flow_payload', 'sniffer-commands', params=params)

				# REDIS send message to sniffer
				# fid = message['flowid']
				# flow = session.flows[fid]
				data = {}
				if len(payload) == 0:
					payload = "[no payload]"
				data['payload'] = payload
				data['type'] = cmd
				ws.send(dumps(data))
				continue

	return ""