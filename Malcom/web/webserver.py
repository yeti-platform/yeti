#!/usr/bin/python
# -*- coding: utf-8 -*-

__description__ = 'Malcom - Malware communications analyzer'
__author__ = '@tomchop_'
__version__ = '1.3 alpha'
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
from flask import Flask, request, render_template, redirect, url_for, g, make_response, abort, flash, send_from_directory, Response, session
from flask.ext.login import LoginManager, login_user, login_required, logout_user, current_user
from functools import wraps

# websockets / WSGI
from geventwebsocket.handler import WebSocketHandler
from gevent.pywsgi import WSGIServer
import gevent

# multiprocessing
from multiprocessing import Process

# custom
from Malcom.auxiliary.toolbox import *
from Malcom.model.model import Model as ModelClass
from Malcom.model.user_management import UserManager as UserManagerClass
from Malcom.web.messenger import WebMessenger

ALLOWED_EXTENSIONS = set(['txt', 'csv'])

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.debug = True
lm = LoginManager()

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


# Custom decorators =============================================

def user_is_admin(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if not current_user.admin:
			abort(404)
		return f(*args, **kwargs)
	return decorated_function

def can_view_sniffer_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id = kwargs['session_id']
		session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})

		if not session_info or (session_info['id'] not in current_user.sniffer_sessions and not session_info['public']):
			debug_output("Sniffing session '%s' does not exist" % session_id, 'error')
			flash("Sniffing session '%s' does not exist" % session_id, 'warning')
			return redirect(url_for('sniffer'))

		kwargs['session_info'] = session_info
		return f(*args, **kwargs)

	return decorated_function

def can_modify_sniffer_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id = kwargs['session_id']
		session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})

		if not session_info or session_info['id'] not in current_user.sniffer_sessions:
			debug_output("Sniffing session '%s' does not exist" % session_id, 'error')
			flash("Sniffing session '%s' does not exist" % session_id, 'warning')
			return redirect(url_for('sniffer'))

		kwargs['session_info'] = session_info
		return f(*args, **kwargs)

	return decorated_function


# import Blueprints =============================================

from Malcom.web.websockets import malcom_websockets
from Malcom.web.api import malcom_api
app.register_blueprint(malcom_websockets, url_prefix='/websocket')
app.register_blueprint(malcom_api, url_prefix='/api')


# Requests ======================================================

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
	if value:
		return value.strftime(format)
	else:
		return "None"

@app.template_filter('display_iterable')
def display_iterable(value):
	if len(value) > 0:
		return ", ".join(value)
	else:
		return "N/A"

@app.template_filter('display_other')
def display_other(value):
	if type(value) in [str, unicode]:
		return value
	elif type(value) == list and len(value) > 0:
		return ", ".join(value)
	elif type(value) == datetime.datetime:
		return value.strftime('%Y-%m-%d %H:%M')

	return "N/A"


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
	g.messenger = app.config['MESSENGER']
	if not 'Model' in g:
		g.Model = app.config['MODEL']
	if not 'UserManager' in g:
		g.UserManager = app.config['USER_MANAGER']

	if g.config['AUTH']:
		g.user = current_user
	else:
		g.user = None

# Authentication stuff ==========================================

@lm.token_loader
def load_token(token):
	print "Load token"
	u = g.UserManager.get_user(token=token)
	if u:
		u.last_activity = datetime.datetime.utcnow()
		u = g.UserManager.save_user(u)
	return u

@lm.user_loader
def load_user(username):
	print "Load user"
	u = g.UserManager.get_user(username=username)
	if u:
		u.last_activity = datetime.datetime.utcnow()
		u = g.UserManager.save_user(u)
	return u

@lm.request_loader
def load_user_from_request(request):
	print "Load user from request"
	api_key = request.headers.get("X-Malcom-API-Key")
	if not app.config['AUTH']:
		u=g.UserManager.get_default_user()
		return u
	if api_key:
		print "Getting user for API key %s" % api_key
		u = g.UserManager.get_user(api_key=api_key)
		if u:
			u.api_last_activity = datetime.datetime.utcnow()
			u.api_request_count += 1
			u = g.UserManager.save_user(u)
			return u

@app.route("/logout")
@login_required
def logout():
	if 'token' in current_user:
		del current_user['token']
	g.UserManager.save_user(current_user)
	logout_user()
	return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():

	if g.user != None:
		if g.user.is_authenticated():
			return redirect(url_for('index'))

	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		rememberme = bool(request.form.get('rememberme', False))
		print "Login attempt for %s (rememberme: %s)" % (username, rememberme)

		# get user w/ username
		user = g.UserManager.get_user(username=username)

		# check its password
		if user and user.check_password(password):
			print "Success!"
			user.get_auth_token()
			g.UserManager.save_user(user)
			login_user(user, remember=rememberme)
			return redirect(request.args.get("next") or url_for("index"))
		else:
			flash("Wrong username / password combination",'error')
			return redirect(url_for('login'))
	else:
		return render_template('login.html')

# Index ========================================================



@app.route('/')
@login_required
def index():
	return redirect(url_for('search'))

# Account ======================================================

@app.route("/account/settings", methods=['GET','POST'])
@login_required
def account_settings():
	if request.method == 'POST':
		if request.form.get('current-password'): # user is asking to change their password

			current = request.form.get('current-password')
			new = request.form.get('new-password')
			repeatnew = request.form.get('repeat-new-password')

			if not current_user.check_password(current):
				flash("Current password does not match.", 'error')
				return redirect(url_for('account_settings'))
			if new != repeatnew:
				flash("The passwords do not match.", 'error')
				return redirect(url_for('account_settings'))

			current_user.reset_password(new)
			g.UserManager.save_user(current_user)
			flash('Password changed successfully!', 'success')
			return redirect(url_for('account_settings'))

	return render_template('account/settings.html')

@app.route("/account/sessions")
@login_required
def account_sessions():
	sniffer_sessions = len(current_user.sniffer_sessions) > 0
	return render_template('account/sessions.html', sniffer_sessions=sniffer_sessions)

@app.route("/account/yara")
@login_required
def account_yara():
	return render_template('account/yara.html')


# feeds ========================================================


# if Malcom.config['FEEDS']:

@app.route('/feeds')
@login_required
def feeds():
	# REDIS query to feed engine
	feed_list = loads(g.messenger.send_recieve('feedList', 'feeds'))
	# alpha = sorted(Malcom.feed_engine.feeds, key=lambda name: name)
	return render_template('feeds.html', feed_names=[n for n in feed_list], feeds=feed_list)

@app.route('/feeds/run/<feed_name>')
@login_required
def run_feed(feed_name):
	# REDIS query to feed engine
	result = g.messenger.send_recieve('feedRun', 'feeds', params={'feed_name':feed_name})
	return redirect(url_for('feeds'))


# graph operations =============================================

@app.route('/nodes/<field>/<path:value>')
@login_required
def nodes(field, value):
	return render_template('nodes.html', field=field, value=value)







# dataset operations ======================================================

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/search/', methods=['GET', 'POST'])
@login_required
def search(term=""):

	# Create a result set with whichever paremeters we have
	if request.method == 'POST':
		field = 'value'
		query = [{field: r.strip()} for r in request.form['bulk-text'].split('\r\n') if r.strip() != '']
		result_set = g.Model.find({'$or': query})
	else:
		query = request.args.get('query', False)
		if query:
			query = query.strip()
		field = request.args.get('field', 'value').strip()
		if not bool(request.args.get('strict', False)):
			result_set = g.Model.find({field: query})
		else:
			result_set = g.Model.find({field: re.compile(re.escape(query), re.IGNORECASE)})

	# user did not specify a query
	if query == False:
		return render_template('search.html', history=g.Model.get_history())
	else:
		# user has specified an empty query
		if query == "":
			flash('Empty search query is empty.')
			return redirect(url_for('search'))			

	# query passed tests, process the result set
	base_elts = []
	base_ids = []
	evil_elts = {}

	for e in result_set:
		base_elts.append(e)
		base_ids.append(e['_id'])
		if 'evil' in e['tags']:
			evil_elts[e['_id']] = e

	# The search yield no results

	if len(base_elts) == 0 and request.method == 'GET':
		if not bool(request.args.get('log', False)):
			flash('"{}" was not found. Use the checkbox above to add it to the database'.format(query))
			return render_template('search.html', term=query, history=g.Model.get_history())
		else:
			new = g.Model.add_text([query], tags=['search'])
			if new:
				flash('"{}" was not found. It was added to the database (ID: {})'.format(query, new['_id']))
				g.Model.add_to_history(query)
			else:
				flash('"{}" did not convert to a viable datatype'.format(query))
			# or do the redirection here
			return render_template('search.html', term=query, history=g.Model.get_history())
	
	if len(base_elts) == 0 and request.method == 'POST':
		flash('Your query did not yield any results. Use the checkbox above to add it to the database')
		return render_template('search.html', history=g.Model.get_history())

	return find_related(field, query, base_elts, base_ids, evil_elts)

def find_related(field, query, base_elts, base_ids, evil_elts):

	# get all 1st degree nodes in one dict

	first_degree = {}

	data = g.Model.find_neighbors({ '_id' : {'$in': base_ids}})
	nodes = data['nodes']
	edges = data['edges']

	all_nodes_dict = { n['_id']: n for n in nodes}
	all_edges_dict = { e['_id']: e for e in edges}

	filtered_edges_dict = {}
	for key, edge in all_edges_dict.items():
		if all_nodes_dict.get(edge['src'], False):
			filtered_edges_dict[key] = edge

	# all_nodes_dict 		contains an id_dictionary with all neighboring nodes
	# filtered_edges_dict 	contains an id_dictionary of all links of which the source is in all_nodes_dict
	# all_edges_dict 		contains an id_dictionary of all 1st degree and 2nd degree links

	linked_elements = {}

	for e in filtered_edges_dict.values():

		if all_nodes_dict.get(e['dst'], False): # if edge points towards one of base_elts
			dst = all_nodes_dict[e['dst']]
			src = all_nodes_dict[e['src']]
			if e['attribs'] not in linked_elements: # if we don't have a record for this link, create an empty array
				linked_elements[e['attribs']] = {}
			if dst['value'] not in linked_elements[e['attribs']]: # avoid duplicates
				linked_elements[e['attribs']][dst['value']] = []
			linked_elements[e['attribs']][dst['value']].append(src)
			if src.get('evil', False):
				evil_elts[src['_id']] = src

	related_elements = {}

	chrono = datetime.datetime.utcnow()
	for n in all_nodes_dict:
		n = all_nodes_dict[n]
		if n['type'] not in related_elements: # if we don't have a record for this type, create an empty array
			related_elements[n['type']] = []
		related_elements[n['type']].append(n)
		if n.get('evil', False):
			evil_elts[n['_id']] = n

	# display fields
	base_elts[0]['fields'] = base_elts[0].display_fields
	return render_template("results.html", field=field, value=query, base_elts=base_elts, evil_elts=evil_elts, linked=linked_elements, related_elements=related_elements)


@app.route('/populate/')
@login_required
def populate():
	return render_template("populate.html")

@app.route('/dataset/')
@login_required
def dataset():
	return render_template("dataset.html")

@app.route('/dataset/clear/')
@login_required
@user_is_admin
def clear():
	g.Model.clear_db()
	return redirect(url_for('dataset'))

@app.route('/dataset/csv')
@login_required
def dataset_csv():

	filename = []
	query = {}

	regex = bool(request.args.get('regex', False))

	for key in request.args:
		if key != '' and key not in ['regex']:
			if regex:
				# slow
				query[key] = re.compile(request.args[key], re.IGNORECASE)
			else:
				# skip regex to make it faster
				query[key] = request.args[key]
			filename.append("%s_%s" % (key, request.args[key]))
		else:
			filename.append('all')

	filename = "-".join(filename)
	results = g.Model.find(query).sort('date_created', -1)

	if results.count() == 0:
		flash("You're about to download an empty .csv",'warning')
		return redirect(url_for('dataset'))
	else:
		response = make_response()
		response.headers['Cache-Control'] = 'no-cache'
		response.headers['Content-Type'] = 'text/csv'
		response.headers['Content-Disposition'] = 'attachment; filename='+filename+'-extract.csv'
		data = u"{},{},{},{},{},{}\n".format('Value', 'Type', 'Tags', 'Created', 'Updated', "Analyzed")

		for e in results:
			data += u"{},{},{},{},{},{}\n".format(e.get('value', "-"), e.get('type', "-"), ";".join(e.get('tags', [])), e.get('date_created', "-"), e.get('date_updated', "-"), e.get('last_analysis', "-"))

		response.data = data
		response.headers['Content-Length'] = len(response.data)

		return response


@app.route('/populate/add', methods=['POST'])
@login_required
def add_data():

	file = request.files.get('bulk-file')

	# deal with file uploads
	if file:
		elements = file.read().split("\n")

	# deal with raw-text
	if request.form.get('bulk-text'):
		elements = request.form.get('bulk-text').split("\n")

	# deal with single element add
	if request.form.get('value'): #
		e = request.form.get('value')
		tags = request.form.get('tags', None)
		if tags:
			e = e + ";{}".format(tags)
		elements = [e]

	if len(elements) == 0:
		flash("You must specify some elements", 'warning')
		return redirect(url_for('dataset'))

	for e in elements:
		if ";" in e:
			elt, tag = e.split(';')
			g.Model.add_text([elt], tag.split(','))
		else:
			g.Model.add_text([e])

	return redirect(url_for('dataset'))





# Sniffer ============================================

@app.route('/sniffer/',  methods=['GET', 'POST'])
@login_required
def sniffer():
	if request.method == 'POST':

		filter = request.form['filter']

		session_name = secure_filename(request.form['session_name'])
		if session_name == "":
			flash("Please specify a session name", 'warning')
			return redirect(url_for('sniffer'))

		debug_output("Creating session %s" % session_name)

		# intercept TLS?
		# intercept_tls = True if request.form.get('intercept_tls', False) and g.config.sniffer_engine.tls_proxy != None else False
		intercept_tls = True if request.form.get('intercept_tls', False) == 'on' else False
		print "Intercept TLS: %s" % intercept_tls

		file = request.files.get('pcap-file').read()

		if not file and not g.config['SNIFFER_NETWORK']:
			flash("Please specify a PCAP file", 'warning')
			return redirect(url_for('sniffer'))


		params = {  'session_name': session_name,
					'remote_addr' : str(request.remote_addr),
					'filter': filter,
					'intercept_tls': intercept_tls,
					'public': True if request.form.get('public', False) else False,
					'pcap': True if file else False,
				}

		# REDIS send message to sniffer w/ params
		session_id = str(loads(g.messenger.send_recieve('newsession', 'sniffer-commands', params=params)))
		session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})
		# this is where the data will be stored persistently
		# if we're dealing with an uploaded PCAP file
		if file:
			# store in /sniffer folder
			with open(g.config['SNIFFER_DIR'] + "/" + session_info['pcap_filename'], 'wb') as f:
				f.write(file)

		# associate sniffer session with current user
		current_user.add_sniffer_session(session_id)
		g.UserManager.save_user(current_user)
		debug_output("Added session %s for user %s" % (session_id, current_user.username))

		# if requested, start sniffing right away
		if request.form.get('startnow', None):
			# REDIS send message to sniffer to start
			g.messenger.send_recieve('sniffstart', 'sniffer-commands', params= {'session_id': session_id, 'remote_addr': str(request.remote_addr)} )

		return redirect(url_for('sniffer_session', session_id=session_id))

	return render_template('network_session_new.html')


@app.route('/sniffer/<session_id>/')
@login_required
@can_view_sniffer_session
def sniffer_session(session_id, session_info=None):
	return render_template('network_session.html', session=session_info, session_name=session_info['name'])


@app.route("/sniffer/<session_id>/<flowid>/raw")
@login_required
@can_view_sniffer_session
def send_raw_payload(session_id, flowid, session_info=None):

	session_id = session_info['id']

	payload = g.messenger.send_recieve('get_flow_payload', 'sniffer-commands', params={'session_id': session_id, 'flowid':flowid})

	if payload == False:
		abort(404)

	response = make_response()
	response.headers['Cache-Control'] = 'no-cache'
	response.headers['Content-Type'] = 'application/octet-stream'
	response.headers['Content-Disposition'] = 'attachment; filename=%s_%s_dump.raw' % (session_info['name'], flowid)
	response.data = payload.decode('base64')
	response.headers['Content-Length'] = len(response.data)

	return response




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
	def __init__(self, auth, listen_port, listen_interface, setup):
		super(MalcomWeb, self).__init__()
		self.setup = setup
		self.listen_port = setup['LISTEN_PORT']
		self.listen_interface = setup['LISTEN_INTERFACE']
		self.http_server = None

	def run(self):
		self.start_server()

	def stop_server(self):
		pass

	def start_server(self):
		if not self.setup['AUTH']:
			app.config['LOGIN_DISABLED'] = True

		app.config['MODEL'] = ModelClass(self.setup)
		app.config['USER_MANAGER'] = UserManagerClass(self.setup)

		lm.init_app(app)
		lm.login_view = 'login'
		lm.session_protection = 'strong'
		lm.anonymous_user = app.config['USER_MANAGER'].get_default_user

		for key in self.setup:
			app.config[key] = self.setup[key]
		app.config['UPLOAD_DIR'] = ""

		app.config['MESSENGER'] = WebMessenger()

		sys.stderr.write("[+] Starting webserver...\n")
		self.http_server = WSGIServer((self.listen_interface, self.listen_port), malcom_app, handler_class=WebSocketHandler)
		sys.stderr.write("[+] Webserver listening on http://%s:%s\n\n" % (self.listen_interface, self.listen_port))

		try:
			self.http_server.serve_forever()
		except KeyboardInterrupt, e:
			pass



