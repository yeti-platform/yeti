
from bson.json_util import dumps, loads
from bson.objectid import ObjectId
from flask import Blueprint, render_template, abort, request, g, url_for, send_from_directory
from flask_restful import Resource, reqparse, Api
import pymongo

from Malcom.auxiliary.toolbox import *
from Malcom.web.webserver import Model, UserManager
from Malcom.web.webserver import login_required, user_is_admin, can_modify_sniffer_session, can_view_sniffer_session
from flask.ext.login import current_user
from webserver import app


malcom_api = Blueprint('malcom_api', __name__)

api=Api(app)
# Public API ================================================

parser = reqparse.RequestParser()
parser.add_argument('search', type=str)
class Search_API(Resource):
	def post(self):
		args=parser.parse_args()
		if 'search' in args:
			criteria=args['search']
			print {'value': '/'+criteria+'/'}
			result=Model.find({'value':{"$regex":"/"+criteria+"/"}})
			return dumps(result)
api.add_resource(Search_API,'/api/search')
# @malcom_api.route('/neighbors/')
# @login_required
# 
# class Neigbors(Resource):
# 	def get(self):
# 		query = {}
# 		for key in request.args:
# 			if key == '_id':
# 				query[key] = {"$in" : [ObjectId(id) for id in request.args.getlist(key)]}
# 			else:
# 				query[key] = {"$in" : request.args.getlist(key)}
# 	
# 		data = Model.find_neighbors(query, include_original=True)
# 		return dumps(data)
# 		
# 	
# 
# @malcom_api.route('/evil/')
# @login_required
# class Evil(Resource):
# 	def get(self):
# 		query = {}
# 		depth = int(request.args.get('depth', 2))
# 		if depth > 2: depth = 2
# 	
# 		for key in request.args:
# 			if key not in ['depth']:
# 				query[key] = request.args.getlist(key)
# 		data = Model.multi_graph_find(query, {'key':'tags', 'value': 'evil'})
# 
# 		return dumps(data)
# 
# 	
# 
# 
# @malcom_api.route('/query/') # ajax method for sarching dataset and populating dataset table
# @login_required
# def query_data():
# 
# 	query = {}
# 
# 	page = int(request.args.get('page', 0))
# 	per_page = int(request.args.get('per_page', 50))
# 	if per_page > 500: per_page = 500
# 	fuzzy = True if request.args.get('fuzzy', False) == 'true' else False
# 	for key in request.args:
# 		if key not in ['page', 'fuzzy', 'per_page']:
# 				if request.args[key].find(',') != -1: # split request arguments
# 						if fuzzy:
# 								#query['$and'] = [{ key: re.compile(split, re.IGNORECASE)} for split in request.args[key].split(',')]
# 								query['$and'] = [{ key: re.compile(split)} for split in request.args[key].split(',')]
# 						else:
# 								query['$and'] = [{ key: split} for split in request.args[key].split(',')]
# 				else:
# 						if fuzzy:
# 								#query[key] = re.compile(request.args[key], re.IGNORECASE) # {"$regex": request.args[key]}
# 								query[key] = re.compile(request.args[key]) # {"$regex": request.args[key]}
# 						else:
# 								query[key] = request.args[key]
# 
# 	data = {}
# 	chrono_query = datetime.datetime.utcnow()
# 
# 	print "Query: ", query
# 	if fuzzy:
# 		elts = list(Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]).hint([('date_created', -1), ('value', 1)]))
# 	else:
# 		elts = list(Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]))
# 
# 	chrono_query = datetime.datetime.utcnow() - chrono_query
# 
# 	data['page'] = page
# 	data['per_page'] = per_page
# 
# 	for elt in elts:
# 		elt['link_value'] = url_for('nodes', field='value', value=elt['value'])
# 		elt['link_type'] = url_for('nodes', field='type', value=elt['type'])
# 	if len(elts) > 0:
# 		data['fields'] = elts[0].display_fields
# 		data['elements'] = elts
# 	else:
# 		data['fields'] = [('value', 'Value'), ('type', 'Type'), ('tags', 'Tags')]
# 		data['elements'] = []
# 	chrono_count = datetime.datetime.utcnow()
# 	if not fuzzy:
# 		data['total_results'] = Model.find(query).count()
# 	else:
# 		data['total_results'] = "many"
# 	chrono_count = datetime.datetime.utcnow() - chrono_count
# 
# 	data['chrono_query'] = str(chrono_query)
# 	data['chrono_count'] = str(chrono_count)
# 
# 	return (dumps(data), 200, {'Content-Type': 'application/json'})
# 
# 
# @malcom_api.route('/dataset/remove/<id>/')
# @login_required
# def delete(id):
# 	result = Model.remove_by_id(id)
# 	return (dumps(result), 200, {'Content-Type': 'application/json'})
# 
# 
# @malcom_api.route('/sniffer/sessionlist/')
# @login_required
# def sniffer_sessionlist():
# 	params = {}
# 
# 	if 'user' in request.args:
# 		params['user'] = current_user.username
# 	if 'page' in request.args:
# 		params['page'] = int(request.args.get('page'))
# 	if 'private' in request.args:
# 		params['private'] = True
# 
# 	session_list = loads(g.messenger.send_recieve('sessionlist', 'sniffer-commands', params=params))
# 	return (dumps({'session_list': session_list}), 200, {'Content-Type': 'application/json'})
# 
# @malcom_api.route('/sniffer/<session_id>/delete/')
# @login_required
# @can_modify_sniffer_session
# def sniffer_session_delete(session_id, session_info=None):
# 	session_id = session_info['id']
# 
# 	result = g.messenger.send_recieve('sniffdelete', 'sniffer-commands', {'session_id': session_id})
# 
# 	if result == "notfound": # session not found
# 		return (dumps({'status':'Sniffer session %s does not exist' % session_id, 'success': 0}), 200, {'Content-Type': 'application/json'})
# 
# 	if result == "running": # session running
# 		return (dumps({'status':"Can't delete session %s: session running" % session_id, 'success': 0}), 200, {'Content-Type': 'application/json'})
# 
# 	if result == "removed": # session successfully stopped
# 		current_user.remove_sniffer_session(session_id)
# 		UserManager.save_user(current_user)
# 		return (dumps({'status':"Sniffer session %s has been deleted" % session_id, 'success': 1}), 200, {'Content-Type': 'application/json'})
# 
# @malcom_api.route('/sniffer/<session_id>/pcap')
# @login_required
# @can_view_sniffer_session
# def pcap(session_id, session_info=None):
# 	session_id = session_info['id']
# 
# 	result = g.messenger.send_recieve('sniffpcap', 'sniffer-commands', {'session_id': session_id})
# 	return send_from_directory(g.config['SNIFFER_DIR'], session_info['pcap_filename'], mimetype='application/vnd.tcpdump.pcap', as_attachment=True, attachment_filename='malcom_capture_'+session_id+'.pcap')