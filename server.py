# custom
from toolbox import *
from analytics import *
from feeds import *
from datatypes.element import Hostname
import netsniffer

#db 
from pymongo import MongoClient

#json / bson
from bson.objectid import ObjectId
from bson.json_util import dumps, loads

#functions
import os, datetime, time, sys, signal
import netifaces as ni

#flask stuff
from werkzeug import secure_filename
from flask import Flask, request, render_template, redirect, url_for, g, make_response, abort

#websockets
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer


UPLOAD_FOLDER = '/home/tomchop/python/cifpy-flask/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'csv'])

app = Flask(__name__)

app.config['DEBUG'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['LISTEN_INTERFACE'] = "0.0.0.0"
app.config['LISTEN_PORT'] = 8080

sniffer_sessions = {}
analytics_engine = Analytics()

@app.errorhandler(404)
def page_not_found(error):
    return 'This page does not exist', 404

@app.after_request
def after_request(response):
	origin = request.headers.get('Origin', '')
	debug_output(origin, False)
	response.headers['Access-Control-Allow-Origin'] = origin
	response.headers['Access-Control-Allow-Credentials'] = 'true'
	return response

@app.before_request
def before_request():
    g.a = analytics_engine
    g.ifaces = {}
    for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
    	g.ifaces[i] = ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']

@app.route('/')
def index():
	return redirect(url_for('dataset'))


# graph operations =============================================

@app.route('/nodes/<field>/<path:value>')
def nodes(field, value):
	return render_template('dynamic_nodes.html', field=field, value=value)


@app.route('/graph/<field>/<path:value>')
def graph(field, value):
	a = g.a 
	base_elts = [e for e in a.data.elements.find( { field: { "$regex": value } })]
	edges, nodes = a.data.get_graph_for_elts(base_elts)
	data = { 'query': base_elts, 'edges': edges, 'nodes': nodes }
	ids = [node['_id'] for node in nodes]
	other = [a for a in a.data.elements.find( {"_id" : { '$not' : { '$in' : ids }}})]
	
	debug_output("query: %s, edges: %s, nodes: %s, other: %s" % (len(base_elts), len(edges), len(nodes), len(other)))
	return (dumps(data))


@app.route('/neighbors/<id>')
def neighbors(id):
	#a = Analytics()
	a = g.a
	elt = a.data.elements.find_one({'_id': ObjectId(id) })

	nodes, edges = a.data.get_neighbors(elt)
	data = { 'query': elt, 'nodes':nodes, 'edges': edges }

	return (dumps(data))


# dataset operations ======================================================

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/dataset/')
def dataset():
	return render_template("dataset.html")

@app.route('/dataset/clear')
def clear():
	#a = Analytics()
	a = g.a
	a.data.clear_db()
	redirect(url_for('dataset.html'))


@app.route('/dataset/list/')
def list(query={}):
	#a = Analytics()
	a = g.a
	query = {}
	for key in request.args:
		query[key] = request.args[key]
	
	debug_output("Search for %s" % query)

	datatypes = ['hostname', 'ip', 'as']
	
	elts = [e for e in a.data.find(query)]

	
	for elt in elts:
		elt['link_value'] = url_for('nodes', field=elt['type'], value=elt[elt['type']])
		elt['link_type'] = url_for('nodes', field='type', value=elt['type'])

	return dumps(elts)
	#return elements


@app.route('/dataset/add', methods=['POST'])
def add_data():
	
	if request.method == "POST":
		file = request.files.get('element-list')
		if file:  #we're dealing with a list of elements
			if allowed_file(file.filename):
				elements = file.read()
				elements = elements.split("\n")
			else:
				return 'filename not allowed'
		else:
			elements = [request.form['element']]

		context = request.form.get('context', None)
		
		if len(elements) == 0 or not context:
			return "You must specify an element and a context"

		a = g.a
		context = context.strip().split(";")
		a.add_text(elements, context)

		if request.form.get('analyse', None):
			a.process()

		return redirect(url_for('dataset'))

	else:
		return "Not allowed"

@app.route('/dataset/remove/<id>')
def delete(id):
	a = g.a #Analytics()
	result = a.data.remove(id)
	return dumps(result)

@app.route('/dataset/clear')
def clear():
	g.a.data.clear_db()
	return redirect(url_for('dataset'))

@app.route('/analytics/')
def analytics():
	g.a.process()
	return "Analytics: Done."

# Sniffer ============================================

@app.route('/sniffer/',  methods=['GET', 'POST'])
def sniffer(session=""):
	if request.method == 'POST':
		filter = request.form['filter']
		session_name = request.form['session_name']
		debug_output("Creating session %s" % session_name)
		sniffer_sessions[session_name] = netsniffer.Sniffer(Analytics(), session_name, str(request.remote_addr), filter, g.ifaces)
		return redirect(url_for('sniffer_session', session_name=session_name))
	return render_template('sniffer_new.html')

@app.route('/sniffer/<session_name>')
def sniffer_session(session_name):
	# if session doesn't exist, create it
	if session_name not in sniffer_sessions:
		abort(404)
	return render_template('sniffer.html', session=sniffer_sessions[session_name], session_name=session_name)
	

@app.route('/sniffer/<session_name>/pcap/')
def pcap(session_name):
	if session_name not in sniffer_sessions:
		abort(404)
	response = make_response()
	response.headers['Cache-Control'] = 'no-cache'
	response.headers['Content-Type'] = 'application/vnd.tcpdump.pcap'
	response.headers['Content-Disposition'] = 'attachment; filename='+session_name+'capture.pcap'
	response.data = sniffer_sessions[session_name].get_pcap()
	response.headers['Content-Length'] = len(response.data)

	return response

@app.route('/analytics_api')
def analytics_api():
	debug_output("Call to analytics API")

	if request.environ.get('wsgi.websocket'):

		ws = request.environ['wsgi.websocket']
		g.a.websocket = ws

		while True:
			try:
				message = loads(ws.receive())
			except Exception, e:
				return ""

			cmd = message['cmd']

			if cmd == 'analyticsstatus':
				if g.a.active:
					send_msg(ws, {'status': 1})
				else:
					send_msg(ws, {'status': 0})

			debug_output("Received: %s" % message)

@app.route('/sniffer_api')
def sniffer_api():
	debug_output("call to sniffer API")

	if request.environ.get('wsgi.websocket'):

		ws = request.environ['wsgi.websocket']

		while True:
			try:
				message = loads(ws.receive())
			except Exception, e:
				debug_output("Could not decode JSON message: %s" %e)
				return ""
			
			debug_output("Received: %s" % message)

			cmd = message['cmd']

			if cmd == 'sessionlist':
				session_list = [s for s in sniffer_sessions]
				send_msg(ws, {'session_list': session_list})
				continue

			session_name = message['session_name']



			if session_name in sniffer_sessions:
				session = sniffer_sessions[session_name]
			else:
				send_msg(ws, "Session %s not foud" % session_name)
				continue

			session.ws = ws

			if cmd == 'sniffstart':
				session.start(str(request.remote_addr))
				#session.send_updates = True
				send_msg(ws, "OK")
				continue

			if cmd == 'sniffstop':
				if session.status():
					session.stop()
					send_msg(ws, 'OK')
				else:
					send_msg(ws, 'Error: sniffer not running')
				continue

			if cmd == 'sniffstatus':
				if session.status():
					status = 'active'
					debug_output("Session %s is active" % session.name)
					send_msg(ws, {'status': 'active', 'session_name': session.name})
				else:
					status = 'inactive'
					debug_output("Session %s is inactive" % session.name)
					send_msg(ws, {'status': 'inactive', 'session_name': session.name})
				continue
					
			if cmd == 'sniffupdate':
				data = session.update()
				if data:
					ws.send(dumps(data))
				continue
		
	return ""



# test functions

def echo(ws):
	while True:
			message = ws.receive()
			ws.send(message)

if __name__ == "__main__":
	
	os.system('clear')
	sys.stderr.write("===== Malcom - Malware Communications Analyzer =====\n\n")
	sys.stderr.write("Starting server...\n")
	sys.stderr.write("Detected interfaces:\n")
	for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
		sys.stderr.write("%s:\t%s\n" % (i, ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']))

	sys.stderr.write("Server running on %s:%s\n\n" % (app.config['LISTEN_INTERFACE'], app.config['LISTEN_PORT']))

	try:
		http_server = WSGIServer((app.config['LISTEN_INTERFACE'], app.config['LISTEN_PORT']), app, handler_class=WebSocketHandler)
		http_server.serve_forever()
	except KeyboardInterrupt:

		sys.stderr.write(" caught: Exiting gracefully\n")

		if len(sniffer_sessions) > 0:
			debug_output('Stopping sniffing sessions...')
			for s in sniffer_sessions:
				sniffer_sessions[s].stop()
		exit(0)
