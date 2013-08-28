import os, sys, threading, time
from toolbox import debug_output
from datetime import timedelta, datetime



class Feed(object):
	"""This is a feed base class. All other feeds must inherit from this class"""
	def __init__(self, name, run_every="24h"):
		self.name = name

		# parse timedelta
		num = int(run_every[:-1])
		if run_every.endswith('s'):
			self.run_every = timedelta(seconds=num)
		if run_every.endswith('m'):
			self.run_every = timedelta(minutes=num)
		if run_every.endswith('h'):
			self.run_every = timedelta(hours=num)
		if run_every.endswith('d'):
			self.run_every = timedelta(days=num)

		self.last_run = None
		self.next_run = datetime.utcnow()
		self.running = False
		self.elements_fetched = 0
		self.status = "OK"
		self.analytics = None

	def update(self):
		"""
		The update() function has to be implemented in each of your feeds.
		Its role is to:
		 - Fetch data from wherever it needs to
		 - Translate this data into elements understood by Malcom (as defined in malcom.datatypes.element)
		 - Save these newly created elements to the database using the self.analytics attribute
		"""
		raise NotImplementedError("update: This method must be implemented in your feed class")

	def run(self):

		self.running = True
		self.last_run = datetime.now()
		self.next_run = self.last_run + self.run_every
		self.elements_fetched = 0

		self.analytics.status = "Feeding"
		status = self.update()
		self.analytics.status = "Working"
		self.analytics.process()
		self.analytics.status = "Inactive"
		self.analytics.notify_progress()
		self.running = False



class FeedEngine(threading.Thread):
	"""Feed engine. This object will load and update feeds"""
	def __init__(self, analytics):
		threading.Thread.__init__(self)
		self.a = analytics
		self.feeds = {}
		self.threads = {}
		self.global_thread = None

		# for periodic tasking
		self.period = 60
		self.run_periodically = False

	def run_feed(self, feed_name):
		if self.threads.get(feed_name):
			if self.threads[feed_name].is_alive():
				return
		self.threads[feed_name] = threading.Thread(None, self.feeds[feed_name].run, None)
		self.threads[feed_name].start()

	def run_all_feeds(self):
		debug_output("Running all feeds")
		for feed_name in [f for f in self.feeds if self.feeds[f].enabled]:
			debug_output('Starting thread for feed %s...' % feed_name)
			self.run_feed(feed_name)

		for t in self.threads:
			if self.threads[t].is_alive():
				self.threads[t].join()
		
		self.a.data.rebuild_indexes()

	def stop_all_feeds(self):
		self.run_periodically = False
		for t in self.threads:
			if self.threads[t].is_alive():
				self.threads[t]._Thread__stop()
		
		self._Thread__stop()

	def run_scheduled_feeds(self):
		for feed_name in [f for f in self.feeds if (self.feeds[f].next_run < datetime.utcnow() and self.feeds[f].enabled)]:	
			debug_output('Starting thread for feed %s...' % feed_name)
			self.run_feed(feed_name)

		for t in self.threads:
			if self.threads[t].is_alive():
				self.threads[t].join()
		
		self.a.data.rebuild_indexes()

	def run(self):
		self.run_periodically = True
		while self.run_periodically:
			time.sleep(self.period) # run a new thread every period seconds
			debug_output("Checking feeds...")
			threading.Thread(None, self.run_scheduled_feeds, None).start()


	def load_feeds(self):
	
		globals_, locals_ = globals(), locals()

		file = os.path.abspath(__file__)
		malcom_directory = os.path.dirname(file)
		
		package_name = 'feeds'
		feeds_dir = malcom_directory + '/' + package_name

		feeds_dir = malcom_directory
		debug_output("Loading feeds in %s" % feeds_dir)
		
		for filename in os.listdir(feeds_dir):
			export_names = []
			export_classes = []

			modulename, ext = os.path.splitext(filename)
			if modulename[0] != "_" and ext in ['.py']:
				subpackage = '%s.%s' % (package_name, modulename)
				
				module = __import__(subpackage, globals_, locals_, [modulename])

				modict = module.__dict__

				names = [name for name in modict if name[0] != '_']
				
				for n in names:
					if n == 'Feed':
						continue
					class_n = modict.get(n)
				 	try:
				 		if issubclass(class_n, Feed) and class_n not in globals_:
				 			new_feed = class_n(n) # create new feed object
				 			new_feed.analytics = self.a # attach analytics instance to feed
				 			self.feeds[n] = new_feed

				 			# this may be for show for now
				 			export_names.append(n)
				 			export_classes.append(class_n)
				 			sys.stderr.write(" + Loaded %s...\n" % n)
				 	except Exception, e:
				 		pass
				 		

		globals_.update((export_names[i], c) for i, c in enumerate(export_classes))

		return export_names, export_classes









