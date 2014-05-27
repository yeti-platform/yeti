#!/usr/bin/python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '1.2 alpha'
__license__ = "GPL"

# patch threads
from gevent import monkey; monkey.patch_socket(dns=False);

# system
import os, datetime, time, sys, signal, argparse, re, pickle
import netifaces as ni

# db 
from pymongo import MongoClient

# json / bson
from bson.objectid import ObjectId
from bson.json_util import dumps, loads
import json

# flask stuff
from werkzeug import secure_filename
from flask import Flask, request, render_template, redirect, url_for, g, make_response, abort, flash, send_from_directory, Response
from functools import wraps

# websockets / WSGI
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer
import gevent

# multiprocessing
from multiprocessing import Process

# custom
from Malcom.auxiliary.toolbox import *
from Malcom.model.model import Model
from Malcom.model.datatypes import Hostname

ALLOWED_EXTENSIONS = set(['txt', 'csv'])
		
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True

Model = Model()


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


@app.errorhandler(404)
def page_not_found(error):
	return 'This page does not exist', 404

@app.after_request
def after_request(response):
	origin = request.headers.get('Origin', '')
	# debug_output(origin, False)
	response.headers['Access-Control-Allow-Origin'] = origin
	response.headers['Access-Control-Allow-Credentials'] = 'true'
	return response

@app.before_request
def before_request():
	# make configuration and analytics engine available to views
	g.config = app.config
	g.model = Model
	g.messenger = app.config['MESSENGER']

# decorator for URLs that should not be public
def private_url(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if app.config['PUBLIC']:
			abort(404)
		return f(*args, **kwargs)
	return decorated_function


@app.route('/')
def index():
	return redirect(url_for('dataset'))

# feeds ========================================================


# if Malcom.config['FEEDS']:

@app.route('/feeds')
def feeds():
	# REDIS query to feed engine
	feed_list = pickle.loads(g.messenger.send_recieve('feedList', 'feeds'))
	# alpha = sorted(Malcom.feed_engine.feeds, key=lambda name: name)
	return render_template('feeds.html', feed_names=[n for n in feed_list], feeds=feed_list)

@app.route('/feeds/run/<feed_name>')
@private_url
def run_feed(feed_name):
	# REDIS query to feed engine
	result = g.messenger.send_recieve('feedRun', 'feeds', params={'feed_name':feed_name})
	return redirect(url_for('feeds'))


# graph operations =============================================

@app.route('/nodes/<field>/<path:value>')
def nodes(field, value):
	return render_template('dynamic_nodes.html', field=field, value=value)


@app.route('/neighbors')
def neighbors():
	query = {}
	for key in request.args:
		query[key] = request.args.getlist(key)

	data = Model.find_neighbors(query, include_original=True)
	return make_response(dumps(data), 200, {'Content-Type': 'application/json'})

@app.route('/evil')
def evil():
	query = {}
	for key in request.args:
		query[key] = request.args.getlist(key)
	data = Model.multi_graph_find(query, {'key':'tags', 'value': 'evil'})

	return (dumps(data), 200, {'Content-Type': 'application/json'})


# dataset operations ======================================================

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/dataset/report/<field>/<path:value>/')
@app.route('/dataset/report/<field>/<path:value>/<strict>/')
def report(field, value, strict=False):
	base_elts_dict = {}
	base_elts = []

	if strict:
		result_set = Model.find({field: value})
	else:
		result_set = Model.find({field: re.compile(re.escape(value), re.IGNORECASE)})

	for e in result_set:
		base_elts_dict[e['_id']] = e
		base_elts.append(e)


	# get all 1st degree nodes in one dict
	all_nodes_dict = {}
	all_edges_dict = {}

	for elt in base_elts:
		nodes, edges = Model.get_neighbors_elt(elt)
		for n in nodes:
			all_nodes_dict[n['_id']] = n
		for e in edges:
			all_edges_dict[e['_id']] = e

	filtered_edges_dict = {}
	for l in all_edges_dict:
		if all_nodes_dict.get(all_edges_dict[l]['src'], False):
			filtered_edges_dict[l] = all_edges_dict[l]

	# all_nodes_dict 		contains an id_dictionary with all neighboring nodes
	# filtered_edges_dict 	contains an id_dictionary of all links of which the source is in all_nodes_dict
	# all_edges_dict 		contains an id_dictionary of all 1st degree and 2nd degree links

	linked_elements = {}

	for e in filtered_edges_dict:
		e = filtered_edges_dict[e]
		
		if all_nodes_dict.get(e['dst'], False): # if edge points towards one of base_elts
			dst = all_nodes_dict[e['dst']]
			src = all_nodes_dict[e['src']]
			if e['attribs'] not in linked_elements: # if we don't have a record for this link, create an empty array
				linked_elements[e['attribs']] = {}
			if dst['value'] not in linked_elements[e['attribs']]: # avoid duplicates
				print "%s is %s for %s" % (dst['value'], e['attribs'], src['value'])
				linked_elements[e['attribs']][dst['value']] = []
			linked_elements[e['attribs']][dst['value']].append(src)

	related_elements = {}

	chrono = datetime.datetime.utcnow()
	for n in all_nodes_dict:
		n = all_nodes_dict[n]
		if n['type'] not in related_elements: # if we don't have a record for this type, create an empty array
			related_elements[n['type']] = []
		related_elements[n['type']].append(n)

	#display fields
	base_elts[0]['fields'] = base_elts[0].display_fields
	return render_template("report.html", field=field, value=value, base_elts=base_elts, linked=linked_elements, related_elements=related_elements)

@app.route('/dataset/')
def dataset():
	return render_template("dataset.html")


@app.route('/dataset/query/') # ajax method for sarching dataset and populating dataset table
def query_data():

	query = {}

	if 'page' in request.args:
		page = int(request.args['page'])
	else:
		page = None


	if 'fuzzy' in request.args:
		fuzzy = request.args['fuzzy'] != 'false'
	else:
		fuzzy = False
	

	for key in request.args:
		if key not in ['page', 'fuzzy']:
				if request.args[key].find(',') != -1: # split request arguments
						if fuzzy:
								#query['$and'] = [{ key: re.compile(split, re.IGNORECASE)} for split in request.args[key].split(',')]
								query['$and'] = [{ key: re.compile(split)} for split in request.args[key].split(',')]
						else:
								query['$and'] = [{ key: split} for split in request.args[key].split(',')]
				else:
						if fuzzy:
								#query[key] = re.compile(request.args[key], re.IGNORECASE) # {"$regex": request.args[key]}
								query[key] = re.compile(request.args[key]) # {"$regex": request.args[key]}
						else:
								query[key] = request.args[key]

	
	apikey = request.headers.get('X-Malcom-API-key', False)

	#if not "X-Malcom-API-key":
	#	return dumps({})

	available_tags = Model.get_tags_for_key(apikey)

	if len(available_tags) > 0:
		tag_filter = {'tags': {'$in': available_tags}}
	else:
		tag_filter = {}

	query = {'$and': [query, tag_filter]}

	data = {}
	chrono_query = datetime.datetime.utcnow()
	if page != None:
		page = int(page)
		per_page = 50
		if fuzzy:
			elts = [e for e in Model.find(query)[page*per_page:page*per_page+per_page].sort('date_created', 1)]#.hint([('_id', 1)])
		else:
			elts = [e for e in Model.find(query)[page*per_page:page*per_page+per_page].sort('date_created', 1)]
		data['page'] = page
		data['per_page'] = per_page
	else:
		elts = [e for e in Model.find(query).sort('date_created', -1)]

	chrono_query = datetime.datetime.utcnow() - chrono_query	
	
	for elt in elts:
		elt['link_value'] = url_for('nodes', field='value', value=elt['value'])
		elt['link_type'] = url_for('nodes', field='type', value=elt['type'])

	if len(elts) > 0:
		data['fields'] = elts[0].display_fields
		data['elements'] = elts
	else:
		data['fields'] = [('value', 'Value'), ('type', 'Type'), ('tags', 'Tags')]
		data['elements'] = []
	
	chrono_count = datetime.datetime.utcnow()
	if not fuzzy:
		data['total_results'] = Model.find(query).count()
	else:
		data['total_results'] = "many"
	chrono_count = datetime.datetime.utcnow() - chrono_count

	data['chrono_query'] = str(chrono_query)
	data['chrono_count'] = str(chrono_count)

	return dumps(data)

@app.route('/dataset/csv')
def dataset_csv():

	filename = []
	query = {}

	if 'fuzzy' in request.args:
		fuzzy = request.args['fuzzy'] != 'false'
	else:
		fuzzy = False
	
	for key in request.args:
		if key != '' and key not in ['fuzzy']:
			if fuzzy:
				# slow
				query[key] = re.compile(request.args[key], re.IGNORECASE)
			else:
				# skip regex to make it faster
				query[key] = request.args[key]
			filename.append("%s_%s" % (key, request.args[key]))
		else:
			filename.append('all')

	filename = "-".join(filename)
	results = Model.find(query).sort('date_created', -1)
	
	if results.count() == 0:
		flash("You're about to download an empty .csv",'warning')
		return redirect(url_for('dataset'))
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
@private_url
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
			tags = request.form.get('tags', None)
		
		if len(elements) == 0:
			flash("You must specify some elements", 'warning')
			return redirect(url_for('dataset'))

		if file: # if we just uploaded a file, and it has associated tags
			for e in elements:
				if ";" in e:
					elt = e.split(';')[0]
					tag = e.split(';')[1]
					Model.add_text([elt], tag.split(','))
				else:
					Model.add_text([e])
		else: # we're inputting from the web
			tags = tags.strip().split(",")
			Model.add_text(elements, tags)

		if request.form.get('analyse', None):
			pass

		return redirect(url_for('dataset'))

	else:
		return "Not allowed"

@app.route('/dataset/remove/<id>')
def delete(id):
	result = Model.remove(id)
	return dumps(result)

@app.route('/dataset/clear/')
@private_url
def clear():
	Model.clear_db()
	return redirect(url_for('dataset'))


# Sniffer ============================================

@app.route('/sniffer/',  methods=['GET', 'POST'])
def sniffer():
	if request.method == 'POST':
		

		filter = request.form['filter']
		
		session_name = secure_filename(request.form['session_name'])
		if session_name == "":
			flash("Please specify a session name", 'warning')
			return redirect(url_for('sniffer'))

		debug_output("Creating session %s" % session_name)

		# intercept TLS?
		intercept_tls = True if request.form.get('intercept_tls', False) and g.config.tls_proxy != None else False

		
		params = {  'session_name': session_name,
					'remote_addr' : str(request.remote_addr),
					'filter': filter,
					'intercept_tls': intercept_tls,
					'filename' : session_name + ".pcap"
				}
		

		
		# this is where the data will be stored persistently

		pcap = None
		# if we're dealing with an uploaded PCAP file
		file = request.files.get('pcap-file')
		if file:
			params['pcap'] = True
			# store in /sniffer folder
			with open(g.config['SNIFFER_DIR'] + "/" + filename, 'wb') as f:
				f.write(file.read())

		#REDIS send message to sniffer w/ params
		g.messenger.send_recieve('newsession', 'sniffer-commands', params=params)

		# start sniffing right away
		if request.form.get('startnow', None):
			# REDIS send message to sniffer to start
			g.messenger.send_recieve('sniffstart', 'sniffer-commands', params= {'session_name': session_name, 'remote_addr': str(request.remote_addr)} )
			#sniffer_session.start(str(request.remote_addr))
		
		return redirect(url_for('sniffer_session', session_name=session_name, pcap_filename=pcap))

	return render_template('sniffer_new.html')

@app.route('/sniffer/sessionlist/')
def sniffer_sessionlist():
	session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
	return dumps({'session_list': session_list})


@app.route('/sniffer/<session_name>/')
def sniffer_session(session_name, pcap_filename=None):
	# check if session exists
	session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
	if session_name not in session_list:
		debug_output("Sniffing session '%s' does not exist" % session_name, 'error')
		flash("Sniffing session '%s' does not exist" % session_name, 'warning')
		return redirect(url_for('sniffer'))
	
	# REDIS query sniffer for info on current session
	session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_name': session_name})
	return render_template('sniffer.html', session=session_info, session_name=session_name)

@app.route('/sniffer/<session_name>/delete')
def sniffer_session_delete(session_name):
	# REDIS query info to stop
	session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
	if session_name not in session_list:
		debug_output("Sniffing session '%s' does not exist" % session_name, 'error')
		flash("Sniffing session '%s' does not exist" % session_name, 'warning')
		return redirect(url_for('sniffer'))

	result = g.messenger.send_recieve('sniffdelete', 'sniffer-commands', {'session_name': session_name})
	
	if result == "notfound": # session not found
		return (dumps({'status':'Sniffer session %s does not exist' % session_name, 'success': 0}), 200, {'Content-Type': 'application/json'})
	
	if result == "running": # session running
		return (dumps({'status':"Can't delete session %s: session running" % session_name, 'success': 0}), 200, {'Content-Type': 'application/json'})
	
	if result == "removed": # session successfully stopped
		return (dumps({'status':"Sniffer session %s has been deleted" % session_name, 'success': 1}), 200, {'Content-Type': 'application/json'})


@app.route('/sniffer/<session_name>/pcap')
def pcap(session_name):
	session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
	if session_name not in session_list:
		debug_output("Sniffing session '%s' does not exist" % session_name, 'error')
		flash("Sniffing session '%s' does not exist" % session_name, 'warning')
		return redirect(url_for('sniffer'))

	result = g.messenger.send_recieve('sniffpcap', 'sniffer-commands', {'session_name': session_name})

	return send_from_directory(g.config['SNIFFER_DIR'], session_name+".pcap", mimetype='application/vnd.tcpdump.pcap', as_attachment=True, attachment_filename='malcom_capture_'+session_name+'.pcap')


@app.route("/sniffer/<session_name>/<flowid>/raw")
def send_raw_payload(session_name, flowid):
	session_list = g.messenger.send_recieve('sessionlist', 'sniffer-commands')
	if session_name not in session_list:
		abort(404)

	payload = g.messenger.send_recieve('get_flow_payload', 'sniffer-commands', params={'session_name': session_name, 'flowid':flowid})
	
	if payload == False:
		abort(404)
			
	response = make_response()
	response.headers['Cache-Control'] = 'no-cache'
	response.headers['Content-Type'] = 'application/octet-stream'
	response.headers['Content-Disposition'] = 'attachment; filename=%s_%s_dump.raw' % (session_name, flowid)
	response.data = payload.decode('base64')
	response.headers['Content-Length'] = len(response.data)

	return response

# Public API ================================================

@app.route('/public/api')
def query_public_api():
	query = {}
	for key in request.args:
		query[key] = request.args.getlist(key)

	apikey = request.headers.get('X-Malcom-API-key', False)

	#if not "X-Malcom-API-key":
	#	return dumps({})

	available_tags = Model.get_tags_for_key(apikey)

	tag_filter = {'tags': {'$in': available_tags}}
	query = {'$and': [query, tag_filter]}

	db_data = Model.find(query)
	data = []
	for d in db_data:
		d['tags'] = list(set(available_tags) & set(d['tags']))
		data.append(d)

	return (dumps(data), 200, {'Content-Type': 'application/json'})


# TEST 

@app.route('/analytics/<query_type>')
def analytics_status(query_type):
	status = g.messenger.send_recieve('%sQuery' % query_type, 'analytics')
	return str(status)


# APIs (websockets) =========================================

# def notify_progress(ws, msg='N/A'):
# 		# REDIS query analytics engine to get status
# 		g.messenger.analytics_ws = ws
# 		while True:
# 			# progress = g.messenger.send_recieve('progressQuery', 'analytics')
# 			# active = g.messenger.send_recieve('statusQuery', 'analytics')
# 			# # progress = 1
# 			# # active = True

# 			# status = {'active': active, 'msg': msg}
# 			# status['progress'] = progress
# 			# send_msg(ws, status, type='analyticsstatus')
# 			gevent.sleep(1)


@app.route('/api/analytics')
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


@app.route('/api/sniffer/realtime/<session_name>')
def sniffer_streaming_api(session_name):
	debug_output("Call to streaming API for session %s" % session_name)

	if request.environ.get('wsgi.websocket'):
		debug_output("Got websocket for session %s" % session_name)
		ws = request.environ['wsgi.websocket']
		g.messenger.websocket_for_session[session_name] = ws

		while True:
			gevent.sleep(1)


@app.route('/api/sniffer')
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
			session_name = message['session_name']

			session = "fail"

			# websocket commands
			params = {'session_name': session_name}

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
				# session.start(str(request.remote_addr), public=g.config['PUBLIC'])
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
					debug_output("Session %s is active" % params['session_name'])
					send_msg(ws, {'status': 'active', 'session_name': params['session_name']}, type=cmd)
				else:
					status = 'inactive'
					debug_output("Session %s is inactive" % params['session_name'])
					send_msg(ws, {'status': 'inactive', 'session_name': params['session_name']}, type=cmd)
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


@app.route("/fast")
def fast():
	return "That was fast!"

@app.route("/slow")
def slow():
	t0 = datetime.datetime.now()
	for i in range(50000):
		Model.elements.find().explain()
	t = datetime.datetime.now()

	return "That was slow... %s\n" % ((t-t0))



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



class MalcomWeb(Process):
	"""docstring for MalcomWeb"""
	def __init__(self, public, listen_port, listen_interface, setup):
		super(MalcomWeb, self).__init__()
		self.setup = setup
		self.public = setup['PUBLIC']
		self.listen_port = setup['LISTEN_PORT']
		self.listen_interface = setup['LISTEN_INTERFACE']
		self.http_server = None
	
	def run(self):
		
		self.start_server()

	def stop_server(self):
		pass

	def start_server(self):
		for key in self.setup:
			app.config[key] = self.setup[key]
		app.config['UPLOAD_DIR'] = ""

		from Malcom.web.messenger import WebMessenger
		app.config['MESSENGER'] = WebMessenger()
		
		sys.stderr.write("[+] Starting webserver...\n")
		self.http_server = WSGIServer((self.listen_interface, self.listen_port), malcom_app, handler_class=WebSocketHandler)
		sys.stderr.write("[+] Webserver listening on http://%s:%s\n\n" % (self.listen_interface, self.listen_port))
		
		try:
			self.http_server.serve_forever()
		except KeyboardInterrupt, e:
			pass
		
		
		
