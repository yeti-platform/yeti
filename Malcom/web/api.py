from flask import Blueprint, render_template, abort, request, g, url_for
from flask.ext.login import current_user

from bson.objectid import ObjectId
from bson.json_util import dumps, loads

from Malcom.web.webserver import Model, login_required, user_is_admin, can_modify_sniffer_session, can_view_sniffer_session
from Malcom.auxiliary.toolbox import *



malcom_api = Blueprint('malcom_api', __name__)


# Public API ================================================


@malcom_api.route('/evil/')
@login_required
def evil():
	query = {}
	for key in request.args:
		query[key] = request.args.getlist(key)
	data = Model.multi_graph_find(query, {'key':'tags', 'value': 'evil'})

	return (dumps(data), 200, {'Content-Type': 'application/json'})


@malcom_api.route('/query/') # ajax method for sarching dataset and populating dataset table
@login_required
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

	return (dumps(data), 200, {'Content-Type': 'application/json'})


@malcom_api.route('/dataset/remove/<id>/')
@login_required
def delete(id):
	result = Model.remove_by_id(id)
	return (dumps(result), 200, {'Content-Type': 'application/json'})


@malcom_api.route('/dataset/clear/')
@login_required
@user_is_admin
def clear():
	Model.clear_db()
	return redirect(url_for('dataset'))


@malcom_api.route('/sniffer/sessionlist/')
@login_required
def sniffer_sessionlist():
	params = {}
	
	if 'user' in request.args:
		params['user'] = current_user.username
	if 'page' in request.args:
		params['page'] = int(request.args.get('page'))
	if 'private' in request.args:
		params['private'] = True

	session_list = loads(g.messenger.send_recieve('sessionlist', 'sniffer-commands', params=params))
	return (dumps({'session_list': session_list}), 200, {'Content-Type': 'application/json'})

@malcom_api.route('/sniffer/<session_id>/delete/')
@login_required
@can_modify_sniffer_session
def sniffer_session_delete(session_id, session_info=None):
	session_id = session_info['id']

	result = g.messenger.send_recieve('sniffdelete', 'sniffer-commands', {'session_id': session_id})
	
	if result == "notfound": # session not found
		return (dumps({'status':'Sniffer session %s does not exist' % session_id, 'success': 0}), 200, {'Content-Type': 'application/json'})
	
	if result == "running": # session running
		return (dumps({'status':"Can't delete session %s: session running" % session_id, 'success': 0}), 200, {'Content-Type': 'application/json'})
	
	if result == "removed": # session successfully stopped
		current_user.remove_sniffer_session(session_id)
		UserManager.save_user(current_user)
		return (dumps({'status':"Sniffer session %s has been deleted" % session_id, 'success': 1}), 200, {'Content-Type': 'application/json'})

@malcom_api.route('/sniffer/<session_id>/pcap')
@login_required
@can_view_sniffer_session
def pcap(session_id, session_info=None):
	session_id = session_info['id']

	result = g.messenger.send_recieve('sniffpcap', 'sniffer-commands', {'session_id': session_id})
	return send_from_directory(g.config['SNIFFER_DIR'], session_info['pcap_filename'], mimetype='application/vnd.tcpdump.pcap', as_attachment=True, attachment_filename='malcom_capture_'+session_id+'.pcap')