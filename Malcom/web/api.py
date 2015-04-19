
from bson.json_util import dumps, loads
from bson.objectid import ObjectId
from flask import Blueprint, render_template, abort, request, g, url_for, send_from_directory
from flask.helpers import make_response
from flask_restful import Resource, reqparse, Api
from flask_restful.representations.json import output_json
import pickle
import pymongo
import werkzeug
from werkzeug.datastructures import FileStorage

from Malcom.auxiliary.toolbox import *
from Malcom.feeds.feed import Feed, FeedEngine
from Malcom.web.webserver import Model, UserManager
from Malcom.web.webserver import login_required, user_is_admin, can_modify_sniffer_session, can_view_sniffer_session
from flask.ext.login import current_user
from webserver import app


malcom_api = Blueprint('malcom_api', __name__)

def output_json(obj, code, headers=None):
    resp = make_response(dumps(obj), code)
    resp.headers.extend(headers or {})
    return resp

api=Api(app)
DEFAULT_REPRESENTATIONS = {'application/json': output_json}
api.representations=DEFAULT_REPRESENTATIONS
class FileStorageArgument(reqparse.Argument):
    def convert(self, value, op):
        if self.type is FileStorage:
            return value

# Public API ================================================


parser = reqparse.RequestParser()
parser.add_argument('search', type=str)
parser.add_argument('_id', type=str)
parser.add_argument('depth', type=str)

parser_neighbor=reqparse.RequestParser()
parser_neighbor.add_argument('_id', type=str)
class Search_API(Resource):
    def post(self):
        args=parser.parse_args()
        if 'search' in args:
            criteria=args['search']
            print {'value': '/'+criteria+'/'}
            result=Model.find({'value':{"$regex":"/"+criteria+"/"}})
            return dumps(result)
api.add_resource(Search_API,'/api/search')
#================================================================

# API PUBLIC for FEEDS===========================================
class FeedsAPI(Resource):
    def get(self, action, feed_name=None):
        if action == 'list':
            return pickle.loads(g.messenger.send_recieve('feedList', 'feeds'))
        if action == 'start':
            return g.messenger.send_recieve('feedRun', 'feeds', params={'feed_name':feed_name})
        if action == 'status':
            feed_list = pickle.loads(g.messenger.send_recieve('feedList', 'feeds'))
            if feed_name in feed_list:
                return {'status':feed_list[feed_name]['status'],'last_run': feed_list[feed_name]['last_run'],'next_run':feed_list[feed_name]['next_run']}
            else:
                return {'status':'KO'}

api.add_resource(FeedsAPI, '/api/feeds/<string:action>', '/api/feeds/<string:action>/<string:feed_name>')

#================================================================

class Neighbors(Resource):
    def get(self):
        query = {}
        for key in request.args:
            if key == '_id':
                query[key] = {"$in" : [ObjectId(id) for id in request.args.getlist(key)]}
            else:
                query[key] = {"$in" : request.args.getlist(key)}

        data = Model.find_neighbors(query, include_original=True)
        return data
api.add_resource(Neighbors,'/api/neighbors/')


class Evil(Resource):
    def get(self):
        args=parser.parse_args()
        query = {}
        if 'depth' in args:
            if args['depth']:
                depth = int(args['depth'])
            else:
                depth=2
        if depth > 2: depth = 2
        for key in args:
            if key not in ['depth']:
                query[key] = request.args.getlist(key)
        data = Model.multi_graph_find(query, {'key':'tags', 'value': 'evil'})
        return data
api.add_resource(Evil,'/api/evil/')


class QueryAPI(Resource):
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

        data = {}
        chrono_query = datetime.datetime.utcnow()

        print "Query: ", query
        print "regex:", regex
        if regex:
            elts = list(Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]).hint([('date_created', -1), ('value', 1)]))
        else:
            elts = list(Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)]))

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
            data['total_results'] = Model.find(query).count()
        else:
            data['total_results'] = "many"
        chrono_count = datetime.datetime.utcnow() - chrono_count

        data['chrono_query'] = str(chrono_query)
        data['chrono_count'] = str(chrono_count)

        return data

api.add_resource(QueryAPI,'/api/query/')


class Delete(Resource):
    def get(self,id):
        result = Model.remove_by_id(id)
        return result

api.add_resource(Delete,'/api/dataset/remove/<id>/')


class SnifferSessionList(Resource):
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
api.add_resource(SnifferSessionList,'/api/sniffer/sessionlist/')


class SnifferSessionDelete(Resource):

    def get(self,session_id):
        result = g.messenger.send_recieve('sniffdelete', 'sniffer-commands', {'session_id': session_id})

        if result == "notfound": # session not found
            return {'status':'Sniffer session %s does not exist' % session_id, 'success': 0}

        if result == "running": # session running
            return {'status':"Can't delete session %s: session running" % session_id, 'success': 0}

        if result == "removed": # session successfully stopped
            current_user.remove_sniffer_session(session_id)
            UserManager.save_user(current_user)
            return {'status':"Sniffer session %s has been deleted" % session_id, 'success': 1}

api.add_resource(SnifferSessionDelete,'/api/sniffer/<session_id>/delete/')


class Pcap(Resource):
    def get(self,session_id):
        result = g.messenger.send_recieve('sniffpcap', 'sniffer-commands', {'session_id': session_id})
        print result
        session=Model.get_sniffer_session(session_id)
        if 'pcap_filename' in session:
            return send_from_directory(g.config['SNIFFER_DIR'],session['pcap_filename'] , mimetype='application/vnd.tcpdump.pcap', as_attachment=True, attachment_filename='malcom_capture_'+session_id+'.pcap')

api.add_resource(Pcap,'/api/sniffer/<session_id>/pcap',endpoint='malcom_api.pcap')


parser_session_pcap_file = reqparse.RequestParser(argument_class=FileStorageArgument)
parser_session_pcap_file.add_argument('pcapfile',type=werkzeug.datastructures.FileStorage, location='files')
parser_session_pcap_str=reqparse.RequestParser()
parser_session_pcap_str.add_argument('session_name',type=str)
parser_session_pcap_str.add_argument('intercept_tls',type=int)
parser_session_pcap_str.add_argument('public',type=int)
parser_session_pcap_str.add_argument('filter',type=int)
class Start_Session(Resource):
    def post(self):
        args=parser_session_pcap_file.parse_args()
        fh_pcap=args['pcapfile']
        args_sessions_params=parser_session_pcap_str.parse_args()
        session_name=args_sessions_params['session_name']
        intercept_tls=bool(args_sessions_params['intercept_tls'])
        public=bool(args_sessions_params['public'])
        filter=''
        if args_sessions_params['filter']:
            filter=args_sessions_params['filter']
        params = {  'session_name': session_name,
                    'remote_addr' : str(request.remote_addr),
                    'filter': filter,
                    'intercept_tls': intercept_tls,
                    'public': public,
                    'pcap': True if fh_pcap else False,
                }
        print params
        session_id = str(loads(g.messenger.send_recieve('newsession', 'sniffer-commands', params=params)))
        session_info = g.messenger.send_recieve('sessioninfo', 'sniffer-commands', {'session_id': session_id})
        # this is where the data will be stored persistently
        # if we're dealing with an uploaded PCAP file
        if fh_pcap:
            # store in /sniffer folder
            fh_pcap.save(g.config['SNIFFER_DIR'] + "/" + session_info['pcap_filename'])
        g.messenger.send_recieve('sniffstart', 'sniffer-commands', params= {'session_id': session_id, 'remote_addr': str(request.remote_addr)} )

        return {'session_id':session_id}
api.add_resource(Start_Session,'/api/session/start/')

#GET data session by _id
#For all data in session: http://localhost:8080/api/<session_id>/?all=1
#For elements by session: http://localhost:8080/api/<session_id>/?all=0&elements=1
#For evil elements by session: http://localhost:8080/api/<session_id>/?all=0&elements=1&evil=1
parser_session=reqparse.RequestParser()
parser_session.add_argument('evil',type=int)
parser_session.add_argument('all',type=int)
parser_session.add_argument('elements',type=int)
class Session(Resource):
    def get(self,session_id):
        args=parser_session.parse_args()
        if 'all' in args:
            if args['all']< 0 or args['all'] >1:
                abort(404)
            else:
                all_data=bool(args['all'])
        evil=False
        elements=False
        if 'evil' in args:
            evil= bool(args['evil'])
        if 'elements' in args:
            elements=bool(args['elements'])

        if session_id:
            data=Model.get_sniffer_session(session_id)
            if data and all_data==True:
                return data
            elif data and elements==True:
                if "session_data" in data:
                    session_data=json.loads(data['session_data'])
                    ids_list=[ ObjectId(session_data['nodes'][k]['_id']['$oid']) for k in session_data['nodes'].keys()]
                    result=Model.find({'_id': {'$in': ids_list}})
                    if evil ==False:
                        return [r for r in result]
                    else:
                        return [ r for r in result if len(r['evil'])> 0]

            else:
                return abort(404)
        else:
            return abort(404)

api.add_resource(Session,'/api/session/<session_id>/')