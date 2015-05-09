import ConfigParser, argparse, os
import netifaces as ni

class MalcomSetup(dict):
	"""Configuraiton loader"""
	def __init__(self):
		super(MalcomSetup, self).__init__()
		
	def save_config():
		raise NotImplemented
		  
	def load_config(self, args):
		self.parse_command_line(args)
		self.sanitize_paths()
		self.get_network_interfaces()

	def sanitize_paths(self):
		if not self['SNIFFER_DIR'].startswith('/'):
			self['SNIFFER_DIR'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'sniffer'))
		if not self['YARA_PATH'].startswith('/'):
			self['YARA_PATH'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'yara'))
		if not self['FEEDS_DIR'].startswith('/'):
			self['FEEDS_DIR'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'feeds'))

	def parse_command_line(self, args):

		if args.config:
			self.parse_config_file(args.config)
		else:
			self['LISTEN_INTERFACE'] = args.interface
			self['LISTEN_PORT'] = args.port
			self['MAX_WORKERS'] = args.max_workers
			self['TLS_PROXY_PORT'] = args.tls_proxy_port
			self['FEEDS'] = args.feeds
			self['SNIFFER'] = args.sniffer
			self['SNIFFER_NETWORK'] = False
			self['SNIFFER_DIR'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'sniffer'))
			self['YARA_PATH'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'yara'))
			self['FEEDS_DIR'] = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'feeds'))
			self['ANALYTICS'] = args.analytics
			self['WEB'] = True
			self['AUTH'] = False

		
	def parse_config_file(self, filename):
		
		config = ConfigParser.ConfigParser(allow_no_value=True)
		config.read(filename)

		sections = config.sections()

		if config.has_section('web'):
			self['WEB'] = config.getboolean('web', 'activated')
			self['LISTEN_INTERFACE'] = config.get('web', 'listen_interface')
			self['LISTEN_PORT'] = config.getint('web', 'listen_port')
			self['AUTH'] = config.getboolean('web', 'auth')

		if config.has_section('analytics'):
			self['ANALYTICS'] = config.getboolean('analytics', 'activated')
			self['MAX_WORKERS'] = config.getint('analytics', 'max_workers')

		if config.has_section('feeds'):
			self['FEEDS'] = config.getboolean('feeds', 'activated')
			self['FEEDS_DIR'] = config.get('feeds', 'feeds_dir')
			self['FEEDS_SCHEDULER'] = config.getboolean('feeds', 'scheduler')

		if config.has_section('sniffer'):
			self['SNIFFER'] = config.getboolean('sniffer', 'activated')
			self['SNIFFER_DIR'] = config.get('sniffer', 'sniffer_dir')
			self['TLS_PROXY_PORT'] = config.getint('sniffer', 'tls_proxy_port')
			self['YARA_PATH'] = config.get('sniffer', 'yara_path')
			self['SNIFFER_NETWORK'] = config.getboolean('sniffer', 'network')

		if config.has_section('database'):
			self['DATABASE'] = {}
			db_params = dict(config.items('database'))
			if 'hosts' in db_params:
				self['DATABASE']['HOSTS'] = db_params['hosts'].split( ',')
			if 'name' in db_params:
				self['DATABASE']['NAME'] = db_params['name']
			if 'username' in db_params:
				self['DATABASE']['USERNAME'] = db_params['username']
			if 'password' in db_params:
				self['DATABASE']['PASSWORD'] = db_params['password']
			if 'authentication_database' in db_params:
				self['DATABASE']['SOURCE'] = db_params['authentication_database']
			if 'replset' in db_params:
				self['DATABASE']['REPLSET'] = db_params['replset']
			if 'read_preferences' in db_params:
				self['DATABASE']['READ_PREF'] = db_params['read_preferences']

		if config.has_section('feeds'):
			self['ACTIVATED_FEEDS'] = []
			for feed in config.options('feeds'):
				self['ACTIVATED_FEEDS'].append(feed)
		

	def get_network_interfaces(self):
		self['IFACES'] = {}
		for i in [i for i in ni.interfaces() if i.find('eth') != -1]:
			self['IFACES'][i] = ni.ifaddresses(i).get(2,[{'addr':'Not defined'}])[0]['addr']

	def to_dict(self):
		return self.__dict__

	def __getattr__(self, name):
		return self.get(name, None)

	def __setattr__(self, name, value):
		self[name] = value
