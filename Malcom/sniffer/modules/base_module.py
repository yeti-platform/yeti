class Module(object):
	"""docstring for Module"""
	def __init__(self):
		pass

	def bootstrap(self):
		raise NotImplementedError("You must implement a bootstrap method")

	def on_packet(self, pkt):
		raise NotImplementedError("You must implement a on_packet(pkt) method")
