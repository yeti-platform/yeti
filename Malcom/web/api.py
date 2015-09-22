from bson.json_util import dumps, loads
from bson.objectid import ObjectId
from bson.objectid import InvalidId
from flask import Blueprint, render_template, abort, request, g, url_for, send_from_directory
from flask.helpers import make_response
from flask_restful import Resource, reqparse, Api, abort as restful_abort
import pickle
import pymongo
import werkzeug

from werkzeug.datastructures import FileStorage
from flask.ext.login import LoginManager, login_user, login_required, logout_user, current_user
from Malcom.auxiliary.toolbox import *
from flask.ext.login import current_user
from webserver import app

from flask_restful_swagger import swagger


class MalcomApi(Api):
    """Custom Malcom API"""

    FORMAT_MIMETYPE_MAP = {
        "csv": "text/csv",
        "json": "application/json",
        "text": "text/html",
        "text": "text/javascript",
        # Add other mimetypes as desired here
    }

    def __init__(self, *args, **kwargs):
        super(MalcomApi, self).__init__(*args, **kwargs)

        self.representations = {
            'text/csv': output_csv,
            'application/json': output_json,
            'text/html': output_standard,
            'text/javascript': output_standard,
            'text/css': output_standard,
        }


    def make_response(self, data, *args, **kwargs):
        """Looks up the representation transformer for the requested media
        type, invoking the transformer to create a response object. This
        defaults to default_mediatype if no transformer is found for the
        requested mediatype. If default_mediatype is None, a 406 Not
        Acceptable response will be sent as per RFC 2616 section 14.1
        :param data: Python object containing response data to be transformed
        """

        default_mediatype = kwargs.pop('fallback_mediatype', None) or self.default_mediatype
        mediatype = MalcomApi.FORMAT_MIMETYPE_MAP.get(request.args.get('output'))

        if default_mediatype in self.mediatypes():
            mediatype = default_mediatype

        if not mediatype:
            if "*/*" in request.accept_mimetypes and len(request.accept_mimetypes) == 1:
                mediatype = default_mediatype
            else:
                mediatype = request.accept_mimetypes.best_match(
                    self.representations,
                    default=default_mediatype,
                )

        if mediatype is None:
            raise NotAcceptable()
        if mediatype in self.representations:
            resp = self.representations[mediatype](data, *args, **kwargs)
            resp.headers['Content-Type'] = mediatype
            return resp
        elif mediatype == 'text/plain':
            resp = original_flask_make_response(str(data), *args, **kwargs)
            resp.headers['Content-Type'] = 'text/plain'
            return resp
        else:
            raise InternalServerError()

malcom_api = Blueprint('malcom_api', __name__)

def output_json(obj, code, headers=None):
    resp = make_response(dumps(obj), code)
    resp.headers.extend(headers or {})
    return resp

def output_csv(data, code, headers=None):
    csv = "{},{},{},{},{},{}\n".format('Value', 'Type', 'Tags', 'First seen', 'Last seen', "Analyzed")
    for d in data:
        csv += "{},{},{},{},{},{}\n".format(d.get('value', "-"), d.get('type', "-"), ";".join(d.get('tags', [])), d.get('date_first_seen', "-"), d.get('date_last_seen', "-"), d.get('last_analysis', "-"))

    resp = make_response(csv, code)
    resp.headers.extend(headers or {})
    return resp

def output_standard(data, code, headers=None):
    resp = make_response(str(data), code)
    resp.headers.extend(headers or {})
    return resp

api = swagger.docs(MalcomApi(app), apiVersion='0.1')

api.representations['text/csv'] = output_csv
api.representations['application/json'] = output_json
api.representations['text/html'] = output_standard

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
    parser = reqparse.RequestParser()
    parser.add_argument('field', type=str, choices=['id', 'value'], required=True, help='Choose from ["id", "value"]')
    parser.add_argument('value', type=str, action='append', required=True)
    @swagger.operation(
        notes='Get neighbors for given elements',
        nickname='neighbors',
        parameters=[
            {
                'name': 'field',
                'description': 'The field to be searched',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'str',
                "allowableValues": {"values": ["id", "value"], "valueType": "LIST" },
            },
            {
                'name': 'value',
                'description': 'Value of the field to be searched',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'str',
            },
        ]
        )
    def get(self):
        args = Neighbors.parser.parse_args()
        field = args['field']
        value = args['value']
        try:
            if field == 'id':
                field = '_id'
                value = [ObjectId(v) for v in value]
        except Exception, e:
            restful_abort(400, reason='{} is an invalid ObjectId'.format(value))

        query = {field: {"$in" : value}}
        # return query
        data = g.Model.find_neighbors(query, include_original=True)
        return data

api.add_resource(Neighbors, '/api/neighbors/')


class Tags(Resource):
    decorators = [login_required]

    @swagger.operation(
        notes='Recursively search for evil elements from a given element',
        nickname='evil',
        )
    def get(self):
        return g.Model.get_tags()

api.add_resource(Tags, '/api/tags/', endpoint="malcom_api.tags")


class Evil(Resource):
    decorators=[login_required]
    parser = reqparse.RequestParser()
    parser.add_argument('id', type=ObjectId, action='append')
    parser.add_argument('depth', type=int, default=2)

    @swagger.operation(
        notes='Recursively search for evil elements from a given element',
        nickname='evil',
        parameters=[
            {
                'name': 'id',
                'description': 'ID of starting element',
                'required': True,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'ObjectId',
            },
            {
                'name': 'depth',
                'description': 'Recursivity depth (max = 2)',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'str',
            },
        ]
        )
    def get(self):
        args = Evil.parser.parse_args()

        depth = args['depth']
        if depth > 2:
            depth = 2

        data = g.Model.multi_graph_find({"_id": args['id']}, {'key':'tags', 'value': 'evil'}, depth=depth)
        return data

api.add_resource(Evil, '/api/evil/')

class QueryAPI(Resource):
    """This resource is used to query / update elements in the Malcom database
    These are the ressources used by scripts in Malcom."""
    decorators=[login_required]

    get_parser = reqparse.RequestParser()
    get_parser.add_argument('query', type=loads, default={})
    get_parser.add_argument('page', type=int, default=0)
    get_parser.add_argument('per_page', type=int, default=50)

    @swagger.operation(
        notes='Query the Malcom database',
        nickname='query',
        parameters=[
            {
                'name': 'query',
                'description': 'A Python-style dictionary containing the request to be made',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'dict',
            },
            {
                'name': 'page',
                'description': 'Page of results to be requested',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'int',
            },
            {
                'name': 'per_page',
                'description': 'Number of results per page',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'int',
            },
        ]
        )

    def get(self):
        args = QueryAPI.get_parser.parse_args()
        query = args['query']
        page = args['page']
        per_page = args['per_page']

        if 'value' in query:
            g.Model.add_to_history(query['value'])

        data = {}
        chrono_query = datetime.datetime.utcnow()

        elts = g.Model.elements.find(query, skip=page*per_page, limit=per_page, sort=[('date_created', pymongo.DESCENDING)])

        chrono_count = datetime.datetime.utcnow()
        data['total_results'] = elts.count()
        chrono_count = datetime.datetime.utcnow() - chrono_count
        elts = list(elts)
        chrono_query = datetime.datetime.utcnow() - chrono_query

        data['chrono_query'] = str(chrono_query)
        data['chrono_count'] = str(chrono_count)

        data['page'] = page
        data['per_page'] = per_page

        for elt in elts:
            elt['link_value'] = url_for('nodes', field='value', value=elt['value'])
            elt['link_type'] = url_for('nodes', field='type', value=elt['type'])

        if data['total_results'] > 0:
            data['fields'] = elts[0].display_fields
            data['elements'] = elts

        return data


    post_parser = reqparse.RequestParser()
    post_parser.add_argument('id', type=ObjectId, location="args", required=True)
    post_parser.add_argument('fields', type=dict, required=True)

    @swagger.operation(
        notes='Update an element in the malcom database',
        nickname='update',
        parameters=[
            {
                'name': 'id',
                'description': 'ID of element to act upon',
                'required': True,
                'paramType': 'query',
                "dataType": 'ObjectId',
            },
            {
                'name': 'fields',
                'description': 'Python-style dictionary containing fields to update',
                'required': True,
                'paramType': 'form',
                "dataType": 'ObjectId',
            },
            ])
    def post(self):
        args = QueryAPI.post_parser.parse_args()
        elt = g.Model.get(_id=args['id'])
        if not elt:
            abort(404)
        elt.update(args['fields'])
        elt = g.Model.save(elt)
        return elt


    delete_parser = reqparse.RequestParser()
    delete_parser.add_argument('id', type=ObjectId, required=True)

    @swagger.operation(
        notes='Remove element from the Malcom database',
        nickname='query',
        parameters=[
            {
                'name': 'id',
                'description': 'ID of element to act upon',
                'required': True,
                'paramType': 'query',
                "dataType": 'ObjectId',
            },
        ])
    def delete(self):
        try:
            _id = request.args.get('id')
        except InvalidId:
            return {'error': 'You must specify an ID'}, 400

        result = g.Model.remove_by_id(_id)
        return result

api.add_resource(QueryAPI, '/api/query/', endpoint="malcom_api.query")


class Data(Resource):
    decorators=[login_required]

    parser = reqparse.RequestParser()
    parser.add_argument('values', type=str, action='append', default=[])
    parser.add_argument('tags', type=str, action='append', default=[])
    parser.add_argument('output', type=str, default='json', choices=['csv', 'json'])

    @swagger.operation(
        notes='Get raw, live data from the Malcom database (can be slow on some queries)',
        nickname='data',
        parameters=[
            {
                'name': 'values',
                'description': 'An array of values',
                'required': False,
                "allowMultiple": True,
                'paramType': 'query',
                "dataType": 'str',
            },
            {
                'name': 'tags',
                'description': 'An array of tags',
                'required': False,
                "allowMultiple": True,
                'paramType': 'query',
                "dataType": 'str',
            },
            {
                'name': 'output',
                'description': 'Output format',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "allowableValues": {"values": ["json", "csv"], "valueType": "LIST" },
                "defaultValue": 'json',
                "dataType": 'str',
            }
        ]
        )
    def get(self):
        args = Data.parser.parse_args()

        values = args.get('values', [])
        if len(values) == 1 and ',' in values[0]:
            values = values[0].split(',')

        tags = args.get('tags', [])
        if len(tags) == 1 and ',' in tags[0]:
            tags = tags[0].split(',')

        query = {"$or": [{'value': {"$in": values}}, {'tags': {"$in": tags}}]}
        cur = list(g.Model.elements.find(query, sort=[('date_created', pymongo.DESCENDING)]))
        return cur

api.add_resource(Data, '/api/data/', endpoint="malcom_api.data")

class Export(Resource):
    """Obtain a pre-generated full database export"""
    decorators=[login_required]
    parser = reqparse.RequestParser()
    parser.add_argument('output', type=str, default='json', choices=['csv', 'json'])
    parser.add_argument('name', required=True, type=str)

    @swagger.operation(
        notes='Retrieve exports done by Malcom',
        nickname='data',
        parameters=[
            {
                'name': 'output',
                'description': 'Output format',
                'required': False,
                "allowMultiple": False,
                'paramType': 'query',
                "allowableValues": {"values": ["json", "csv"], "valueType": "LIST" },
                "defaultValue": 'json',
                "dataType": 'str',
            },
            {
                'name': 'name',
                'description': 'Name of export',
                'required': True,
                "allowMultiple": False,
                'paramType': 'query',
                "dataType": 'str',
            },
        ]
        )
    def get(self):
        args = Export.parser.parse_args()
        output = args['output']
        name = args['name']
        try:
            return send_from_directory(g.config['EXPORTS_DIR'],
                                       'export_{}.{}'.format(name, output),
                                        mimetype=output,
                                     )
        except Exception as e:
            restful_abort(404)


api.add_resource(Export, '/api/export/', endpoint="malcom_api.export")

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

        # return output

        if type(output) is dict:
            return output, 200, {'Content-Type': 'application/json'}
        else:
            return output, 200, {'Content-Type': 'text/html'}

api.add_resource(SnifferSessionList, '/api/sniffer/list/')
api.add_resource(SnifferSessionDelete, '/api/sniffer/delete/<session_id>/')
api.add_resource(SnifferSessionPcap, '/api/sniffer/pcap/<session_id>/', endpoint='malcom_api.pcap')
api.add_resource(SnifferSessionNew, '/api/sniffer/new/', endpoint='malcom_api.session_start')
api.add_resource(SnifferSessionControl, '/api/sniffer/control/<session_id>/<string:action>/', endpoint='malcom_api.session_control')
api.add_resource(SnifferSessionData, '/api/sniffer/data/<session_id>/')
api.add_resource(SnifferSessionModuleFunction, '/api/sniffer/module/<session_id>/<module_name>/<function>/', endpoint='malcom_api.call_module_function')
