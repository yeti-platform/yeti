import ConfigParser, argparse
import netifaces as ni

class MalcomSetup(dict):
	"""Configuraiton loader"""
	def __init__(self):
		super(MalcomSetup, self).__init__()
		
	def save_config():
		raise NotImplemented
		  
	def load_config(self, args):
		self.parse_command_line(args)
		self.get_network_interfaces()

	def parse_command_line(self, args):

		if args.config:
			self.parse_config_file(args.config)
		else:
			self['LISTEN_INTERFACE'] = args.interface
			self['LISTEN_PORT'] = args.port
			self['MAX_WORKERS'] = args.max_workers
			self['AUTH'] = args.auth
			self['TLS_PROXY_PORT'] = args.tls_proxy_port
			self['FEEDS'] = args.feeds
			self['ANALYTICS'] = args.analytics

		
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
