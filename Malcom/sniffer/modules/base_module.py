from ConfigParser import ConfigParser
import os


class Module(object):
	"""docstring for Module"""
	def __init__(self):
		self.load_conf()
	
	def bootstrap(self):
		raise NotImplementedError("You must implement a bootstrap method")

	def on_packet(self, pkt):
		raise NotImplementedError("You must implement a on_packet(pkt) method")
	def load_conf(self):
		self.config={}
		config_file=os.path.join(os.path.dirname(os.path.realpath(__file__)),self.name,self.name+'.conf')
		print config_file
		cfp=ConfigParser()
		if os.path.isfile(config_file):
			cfp.readfp(open(config_file))
			for section in cfp.sections():
				self.config[section]={}
				for option in cfp.options(section):
					self.config[section][option]=cfp.get(section, option)