
from bson.json_util import dumps, loads
from bson.objectid import ObjectId
from bson.objectid import InvalidId
from flask import Blueprint, render_template, abort, request, g, url_for, send_from_directory
from flask.helpers import make_response
from flask_restful import Resource, reqparse, Api
import pickle
import pymongo
import werkzeug
from werkzeug.datastructures import FileStorage
from flask.ext.login import LoginManager, login_user, login_required, logout_user, current_user
from Malcom.auxiliary.toolbox import *
from flask.ext.login import current_user
from webserver import app


malcom_api = Blueprint('malcom_api', __name__)


def output_json(obj, code, headers=None):
    if type(obj) is dict:
        resp = make_response(dumps(obj), code)
    else:
        resp = make_response(obj, code)
    resp.headers.extend(headers or {})
    return resp

api = Api(app)
DEFAULT_REPRESENTATIONS = {
                            'application/html': output_json,
                            'application/json': output_json,
                            'text/html': output_json,
                            'text/javascript': output_json,
                            'text/css': output_json,
                            }

api.representations = DEFAULT_REPRESENTATIONS

class FileStorageArgument(reqparse.Argument):
    def convert(self, value, op):
        if self.type is FileStorage:
            return value


# API PUBLIC for FEEDS===========================================
class FeedsAPI(Resource):
    decorators=[login_required]
    def get(self, action, feed_name=None):
        if action == 'list':
            return pickle.loads(g.messenger.send_recieve('feedList', 'feeds'))
        if action == 'start':
            result = g.messenger.send_recieve('feedRun', 'feeds', params={'feed_name':feed_name})
            if result == 'notfound':
                msg = 'Feed {} not found'.format(feed_name)
            elif result == 'running':
                msg = "Feed {} is running".format(feed_name)
            return {"status": msg}
        if action == 'status':
            feed_list = pickle.loads(g.messenger.send_recieve('feedList', 'feeds'))
            if feed_name in feed_list:
                return {'status':feed_list[feed_name]['status'],'last_run': feed_list[feed_name]['last_run'],'next_run':feed_list[feed_name]['next_run']}
            else:
                return {'status': 'KO'}

api.add_resource(FeedsAPI, '/api/feeds/<string:action>/', '/api/feeds/<string:action>/<string:feed_name>/')

# QUERYING API ================================================================

class Neighbors(Resource):
    decorators=[login_required]
    def get(self):
        query = {}
        for key in request.args:
            if key == '_id':
                query[key] = {"$in" : [ObjectId(id) for id in request.args.getlist(key)]}
            else:
                query[key] = {"$in" : request.args.getlist(key)}

        data = g.Model.find_neighbors(query, include_original=True)
        return data

class Evil(Resource):
    decorators=[login_required]
    parser = reqparse.RequestParser()
    parser.add_argument('_id', type=str)
    parser.add_argument('value', type=str)
    parser.add_argument('depth', type=int, default=2)

    def get(self):
        args = Evil.parser.parse_args()
        query = {}
        depth = args['depth']
        if depth > 2:
            depth = 2

        for key in args:
            if key not in ['depth']:
                query[key] = request.args.getlist(key)

        data = g.Model.multi_graph_find(query, {'key':'tags', 'value': 'evil'}, depth=depth)
        return data

class QueryAPI(Resource):
    decorators=[login_required]
    def get(self):
        query = {}

        page = int(request.args.get('page', 0))
        per_page = int(request.args.get('per_page', 50))
        if per_page > 500: per_page = 500
        regex = True if request.args.get('regex', False) != False else False

        for key in request.args:
            if key not in ['page', 'regex', 'per_page']:
                    if request.args[key].find(',') != -1: # split request arguments
                            if regex:
                                    #query['$and'] = [{ key: re.compile(split, re.IGNORECASE)} for split in request.args[key].split(',')]
                                    query['$and'] = [{ key: re.compile(split)} for split in request.args[key].split(',')]
                            else:
                                    query['$and'] = [{ key: split} for split in request.args[key].split(',')]
                    else:
                            if regex:
                                    #query[key] = re.compile(request.args[key], re.IGNORECASE) # {"$regex": request.args[key]}
                                    query[key] = re.compile(request.args[key]) # {"$regex": request.args[key]}
                            else:
                                    query[key] = request.args[key]

        if query:
            hist = query.get('value')
            if hasattr(hist, 'pattern'):  # do not attempt to store a regex in history.
                g.Model.add_to_history(hist.pattern)
            else:
                g.Model.add_to_history(hist)

        data = {}
        chrono_query = datetime.datetime.utcnow()

        print "Query: ", query
        print "Regex:", regex
        if regex:
            elts = list(g.Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]).hint([('date_created', -1), ('value', 1)]))
        else:
            elts = list(g.Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]))

        chrono_query = datetime.datetime.utcnow() - chrono_query

        data['page'] = page
        data['per_page'] = per_page

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
        if not regex:
            data['total_results'] = g.Model.find(query).count()
        else:
            data['total_results'] = "many"
        chrono_count = datetime.datetime.utcnow() - chrono_count

        data['chrono_query'] = str(chrono_query)
        data['chrono_count'] = str(chrono_count)

        return data

api.add_resource(Neighbors, '/api/neighbors/')
api.add_resource(Evil, '/api/evil/')
api.add_resource(QueryAPI, '/api/query/', endpoint="malcom_api.query")

# DATA MANIPULATION =======================================================


class DatasetAPI(Resource):
    decorators=[login_required]
    def get(self, action):
        if action == 'remove':
            try:
                _id = ObjectId(request.args.get('_id'))
            except InvalidId:
                return {'error': 'You must specify an ID'}, 400

            result = g.Model.remove_by_id(_id)
            return result

        if action == 'add':
            # TODO
            pass

api.add_resource(DatasetAPI, '/api/dataset/<string:action>/')


# SNIFFER API =============================================================


class SnifferSessionList(Resource):
    decorators=[login_required]
    def get(self):
        params = {}
        if 'user' in request.args:
            params['user'] = current_user.username
        if 'page' in request.args:
            params['page'] = int(request.args.get('page'))
        if 'private' in request.args:
            params['private'] = True
        session_list = loads(g.messenger.send_recieve('sessionlist', 'sniffer-commands', params=params))
        return {'session_list': session_list}


class SnifferSessionDelete(Resource):
    decorators=[login_required]
    def get(self, session_id):
        result = g.messenger.send_recieve('sniffdelete', 'sniffer-commands', {'session_id': session_id})
        print "Result", result

        if result == "notfound":  # session not found
            return {'status': 'Sniffer session %s does not exist' % session_id, 'success': 0}

        if result == "running":  # session running
            return {'status': "Can't delete session %s: session running" % session_id, 'success': 0}

        if result == "removed":  # session successfully stopped
            current_user.remove_sniffer_session(session_id)
            g.UserManager.save_user(current_user)
            return {'status': "Sniffer session %s has been deleted" % session_id, 'success': 1}


class SnifferSessionPcap(Resource):
    decorators=[login_required]
    def get(self, session_id):
        result = g.messenger.send_recieve('sniffpcap', 'sniffer-commands', {'session_id': session_id})
        session = g.Model.get_sniffer_session(session_id)
        if 'pcap_filename' in session:
            return send_from_directory(g.config['SNIFFER_DIR'], session['pcap_filename'] , mimetype='application/vnd.tcpdump.pcap', as_attachment=True, attachment_filename='malcom_capture_'+session_id+'.pcap')


class SnifferSessionNew(Resource):
    decorators=[login_required]
    parser = reqparse.RequestParser()
    parser.add_argument('pcapfile', type=werkzeug.datastructures.FileStorage, location='files')
    parser.add_argument('session_name', type=str, required=True)
    parser.add_argument('intercept_tls', type=bool, default=0)
    parser.add_argument('public', type=bool, default=True)
    parser.add_argument('start', type=bool, default=False)
    parser.add_argument('filter', type=str, default='')

    def post(self):
        args_sessions_params = SnifferSessionNew.parser.parse_args()
        fh_pcap = args_sessions_params['pcapfile']
        session_name = args_sessions_params['session_name']
        intercept_tls = args_sessions_params['intercept_tls']
        public = args_sessions_params['public']
        start = args_sessions_params['start']
        _filter = args_sessions_params['filter']

        params = {  'session_name': session_name,
                    'remote_addr' : str(request.remote_addr),
                    'filter': _filter,
                    'intercept_tls': intercept_tls,
                    'public': public,
                    'pcap': True if fh_pcap else False,
                }

        session_id = str(loads(g.messenger.send_recieve('newsession', 'sniffer-commands', params=params)))
        session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})
        # this is where the data will be stored persistently
        # if we're dealing with an uploaded PCAP file
        if fh_pcap:
            # store in /sniffer folder
            fh_pcap.save(g.config['SNIFFER_DIR'] + "/" + session_info['pcap_filename'])

        if start:
            g.messenger.send_recieve('sniffstart', 'sniffer-commands', params={'session_id': session_id, 'remote_addr': str(request.remote_addr)})

        return {'session_id': session_id}


# GET data session by _id
# For all data in session: http://localhost:8080/api/sniffer/data/<session_id>/?all=1
# For elements by session: http://localhost:8080/api/sniffer/data/<session_id>/?elements=1
# For evil elements by session: http://localhost:8080/api/sniffer/data/<session_id>/?evil=1

class SnifferSessionData(Resource):
    decorators = [login_required]
    parser = reqparse.RequestParser()
    parser.add_argument('evil', type=bool, default=False)
    parser.add_argument('all', type=bool, default=False)
    parser.add_argument('elements', type=bool, default=False)

    def get(self, session_id):
        args = SnifferSessionData.parser.parse_args()
        _all = args['all']
        evil = args['evil']
        elements = args['elements']

        session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})

        if not session_info:
            abort(404)

        if _all or not (_all or evil or elements):
            return session_info

        result = g.Model.find({'_id': {'$in': [ObjectId(i) for i in session_info['node_list']]}})

        if elements:
            return {"node_list" : list(result)}

        if evil:
            return {'evil_node_list': [r for r in result if len(r['evil']) > 0]}

        if not (_all or elements or evil):
            abort(400)

class SnifferSessionControl(Resource):
    decorators=[login_required]

    def get(self, session_id, action):
        if action == 'start':
            status = g.messenger.send_recieve('sniffstart', 'sniffer-commands', {'session_id': session_id})
        if action == 'stop':
            status = g.messenger.send_recieve('sniffstop', 'sniffer-commands', {'session_id': session_id})

        return status


class SnifferSessionModuleFunction(Resource):
    decorators=[login_required]
    def get(self, session_id, module_name, function):
        args = request.args
        output = g.messenger.send_recieve('call_module_function', 'sniffer-commands', params={'session_id': session_id, 'module_name': module_name, 'function': function, 'args':args})
        if output is False:
            return "Not found", 404

        return output

        # if type(output) is dict:
        #     return output, 200, {'Content-Type': 'application/json'}
        # else:
        #     return output, 200, {'Content-Type': 'text/html'}

api.add_resource(SnifferSessionList, '/api/sniffer/list/')
api.add_resource(SnifferSessionDelete, '/api/sniffer/delete/<session_id>/')
api.add_resource(SnifferSessionPcap, '/api/sniffer/pcap/<session_id>/', endpoint='malcom_api.pcap')
api.add_resource(SnifferSessionNew, '/api/sniffer/new/', endpoint='malcom_api.session_start')
api.add_resource(SnifferSessionControl, '/api/sniffer/control/<session_id>/<string:action>/', endpoint='malcom_api.session_control')
api.add_resource(SnifferSessionData, '/api/sniffer/data/<session_id>/')
api.add_resource(SnifferSessionModuleFunction, '/api/sniffer/module/<session_id>/<module_name>/<function>/', endpoint='malcom_api.call_module_function')
