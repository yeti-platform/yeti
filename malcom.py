#!/usr/bin/python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '0.3'
__license__ = "GPL"


# custom
from toolbox import *
from analytics import *
from feeds.feed import FeedEngine
from datatypes.element import Hostname
import netsniffer

#db 
from pymongo import MongoClient

#json / bson
from bson.objectid import ObjectId
from bson.json_util import dumps, loads

#system
import os, datetime, time, sys, signal, argparse
import netifaces as ni

#flask stuff
from werkzeug import secure_filename
from flask import Flask, request, render_template, redirect, url_for, g, make_response, abort

#websockets
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer


# for file upload
ALLOWED_EXTENSIONS = set(['txt', 'csv'])

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True

# This enables the server to be ran behind a reverse-proxy
# Make sure you have an nginx configuraiton similar to this

# location = /malcom { rewrite ^ /malcom/; }
# location /malcom { try_files $uri @malcom; }

# # proxy
# location @malcom {
# 	proxy_pass http://127.0.0.1:8080;
# 	proxy_http_version 1.1;
# 	proxy_set_header SCRIPT_NAME /malcom;
# 	proxy_set_header Host $host;    
# 	proxy_set_header X-Scheme $scheme;
# 	proxy_set_header Upgrade $http_upgrade;
# 	proxy_set_header Connection "upgrade";
# }

def malcom_app(environ, start_response):  
	
	if environ.get('HTTP_SCRIPT_NAME'):
		# update path info 
		environ['PATH_INFO'] = environ['PATH_INFO'].replace(environ['HTTP_SCRIPT_NAME'], "")
		# declare SCRIPT_NAME
		environ['SCRIPT_NAME'] = environ['HTTP_SCRIPT_NAME']
	
	if environ.get('HTTP_X_SCHEME'):	
		# forward the scheme
		environ['wsgi.url_scheme'] = environ.get('HTTP_X_SCHEME')

	return app(environ, start_response)


app.config['DEBUG'] = True
app.config['VERSION'] = "0.3"
app.config['UPLOAD_FOLDER'] = ""
app.config['LISTEN_INTERFACE'] = "0.0.0.0"
app.config['LISTEN_PORT'] = 8080


# global avariables, used throughout malcom
sniffer_sessions = {}
analytics_engine = Analytics()
feed_engine = FeedEngine(analytics_engine)

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
	g.version = app.config['VERSION']
	g.a = analytics_engine
	g.ifaces = {}
	for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
		g.ifaces[i] = ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']

@app.route('/')
def index():
	return redirect(url_for('dataset'))

# feeds ========================================================

@app.route('/feeds')
def feeds():
	return render_template('feeds.html', feeds=feed_engine.feeds)

@app.route('/feeds/run/<feed_name>')
def run_feed(feed_name):
	feed_engine.run_feed(feed_name)
	return redirect(url_for('feeds'))


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

@app.route('/neighbors', methods=['POST'])
def neighbors():
	a = g.a
	allnodes = []
	alledges = []

	for id in request.form.getlist('ids'):
		elt = a.data.elements.find_one({'_id': ObjectId(id) })
		nodes, edges = a.data.get_neighbors(elt)
		allnodes += [n for n in nodes if n not in allnodes]
		alledges += [e for e in edges if e not in alledges]
		
	data = { 'query': elt, 'nodes':allnodes, 'edges': alledges }

	return (dumps(data))

@app.route('/evil', methods=['POST'])
def evil():
	a = g.a
	allnodes = []
	alledges = []

	for id in request.form.getlist('ids'):
		elt = a.data.elements.find_one({'_id': ObjectId(id) })
		nodes, edges = a.find_evil(elt)
		allnodes += [n for n in nodes if n not in allnodes]
		alledges += [e for e in edges if e not in alledges]
		
	data = { 'query': elt, 'nodes':allnodes, 'edges': alledges }

	return (dumps(data))


# dataset operations ======================================================

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/dataset/')
def dataset():
	return render_template("dataset.html")


@app.route('/dataset/list/') # ajax method for populating dataset table
def list():
	a = g.a
	query = {}
	for key in request.args:
		query[key] = request.args[key]

	try:
		page = int(query['page'])
	except Exception, e:
		page = 0

	del query['page']

	per_page = 50

	debug_output("Search for %s (page #%s)" % (query, page))
	
	elts = [e for e in a.data.find(query)]
	
	for elt in elts:
		elt['link_value'] = url_for('nodes', field='value', value=elt['value'])
		elt['link_type'] = url_for('nodes', field='type', value=elt['type'])

	data = {}
	if len(elts) > 0:
		data['fields'] = elts[0].display_fields
		data['elements'] = elts[page*per_page:(page+1)*per_page]
	else:
		data['fields'] = [('value', 'Value'), ('type', 'Type'), ('context', 'Context')]
		data['elements'] = []
	
	data['page'] = page
	data['per_page'] = per_page
	data['total_results'] = len(elts)

	return dumps(data)

@app.route('/dataset/list/csv')
def dataset_csv():
	a = g.a
	filename = []
	query = {}
	for key in request.args:
		query[key] = request.args[key]
		filename.append("%s_%s" % (key, query[key]))

	filename = "-".join(filename)

	print query, filename
	
	results = a.data.find(query)
	
	if results.count() == 0:
		data = ""
	else:
		response = make_response()
		response.headers['Cache-Control'] = 'no-cache'
		response.headers['Content-Type'] = 'text/csv'
		response.headers['Content-Disposition'] = 'attachment; filename='+filename+'-extract.csv'
		fields = results[0].display_fields
		data = ";".join([f[1] for f in fields ]) + "\n"
		for e in results:
			data += ";".join([list_to_str(e.get(f[0],"-")) for f in fields]) + "\n"

	response.data = data
	response.headers['Content-Length'] = len(response.data)

	return response


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
	a = g.a 
	result = a.data.remove(id)
	return dumps(result)

@app.route('/dataset/clear/')
def clear():
	g.a.data.clear_db()
	return redirect(url_for('dataset'))

@app.route('/analytics')
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
		if request.form['startnow']:
			sniffer_sessions[session_name].start(str(request.remote_addr))
		return redirect(url_for('sniffer_session', session_name=session_name))
	return render_template('sniffer_new.html')

@app.route('/sniffer/<session_name>/')
def sniffer_session(session_name):
	# if session doesn't exist, create it
	if session_name not in sniffer_sessions:
		abort(404)

	
	return render_template('sniffer.html', session=sniffer_sessions[session_name], session_name=session_name)
	

@app.route('/sniffer/<session_name>/pcap')
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



# APIs =========================================


@app.route('/api/analytics')
def analytics_api():
	debug_output("Call to analytics API")

	if request.environ.get('wsgi.websocket'):
		debug_output("Got websocket")

		ws = request.environ['wsgi.websocket']
		g.a.websocket = ws

		while True:
			try:
				message = loads(ws.receive())
				debug_output("Received: %s" % message)
			except Exception, e:
				return ""

			cmd = message['cmd']

			if cmd == 'analyticsstatus':
				if g.a.active:
					send_msg(ws, {'status': 1})
				else:
					send_msg(ws, {'status': 0})

			


@app.route('/api/sniffer')
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

	# options
	parser = argparse.ArgumentParser(description="Malcom - malware communications analyzer")
	parser.add_argument("-i", "--interface", help="Listen interface", default=app.config['LISTEN_INTERFACE'])
	parser.add_argument("-p", "--port", help="Listen port", type=int, default=app.config['LISTEN_PORT'])
	args = parser.parse_args()

	app.config['LISTEN_INTERFACE'] = args.interface
	app.config['LISTEN_PORT'] = args.port

	sys.stderr.write("===== Malcom %s - Malware Communications Analyzer =====\n\n" % app.config['VERSION'])
	sys.stderr.write("Starting server...\n")
	sys.stderr.write("Detected interfaces:\n")
	for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
		sys.stderr.write("%s:\t%s\n" % (i, ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']))


	sys.stderr.write("Importing feeds...\n")
	feed_engine.load_feeds()

	sys.stderr.write("Server running on %s:%s\n\n" % (app.config['LISTEN_INTERFACE'], app.config['LISTEN_PORT']))

	try:
		http_server = WSGIServer((app.config['LISTEN_INTERFACE'], app.config['LISTEN_PORT']), malcom_app, handler_class=WebSocketHandler)
		http_server.serve_forever()
	except KeyboardInterrupt:

		sys.stderr.write(" caught: Exiting gracefully\n")

		if len(sniffer_sessions) > 0:
			debug_output('Stopping sniffing sessions...')
			for s in sniffer_sessions:
				sniffer_sessions[s].stop()
		exit(0)
