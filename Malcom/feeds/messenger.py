import json, threading, time, pickle, urllib2, sys
from bson import json_util

from Malcom.auxiliary.toolbox import debug_output
from Malcom.shmem.SharedData import Messenger


class FeedsMessenger(Messenger):
	"""REDIS messenger for FeedEngine"""
	def __init__(self, feedengine_instance):
		super(FeedsMessenger, self).__init__()
		self.name = "feeds"
		self.feedengine_instance = feedengine_instance

		debug_output("[+] Feed messenger started")
		self.subscribe_channel('feeds', self.message_handler)


	def message_handler(self, msg):
		msg = json.loads(msg)
		params = msg.get('params', {})
		queryid = msg['queryid']
		src = msg['src']
		msg = msg['msg']

		final_msg = None

		if msg == 'feedList':
			msg = {}
			for feed in self.feedengine_instance.feeds:
				f = self.feedengine_instance.feeds[feed]
				msg[feed] = {  'run_every' : str(f.run_every),
								'last_run' : f.last_run,
								'next_run' : f.next_run,
								'running' : f.running,
								'elements_fetched' : f.elements_fetched,
								'status' : f.status,
								'enabled' : f.enabled,
								'name': f.name,
								'description': f.description,
								'source':f.source
								}

			final_msg = pickle.dumps(msg)

		if msg == 'feedRun':
			result = self.feedengine_instance.run_feed(params['feed_name'])
			if result:
				final_msg = "running"
			else:
				final_msg = "notfound"

		if msg == 'feedToggle':
			pass

		if final_msg != None:
			reply = {'msg': final_msg, 'queryid': queryid, 'dst': src, 'src':self.name}
			self.publish_to_channel('feeds', json.dumps(reply))

		return