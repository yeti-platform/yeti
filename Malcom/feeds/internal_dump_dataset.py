import urllib2
import re
import md5
import os

from bson.json_util import dumps, loads

from Malcom.feeds.feed import Feed


class ExportAll(Feed):
	"""
	This gets data from https://palevotracker.abuse.ch/?rssfeed
	"""
	def __init__(self, name):
		super(ExportAll, self).__init__(name, run_every="1h")
		self.name = "ExportAll"
		self.description = "Export all the dataset to CSV and JSON"
		self.source = "local"
		self.tags = ['private', 'internal']

	def update(self):

		self.output_csv = open('{}/export_all.csv'.format(self.engine.configuration['EXPORTS_DIR']), 'w+')
		self.output_csv.write("{},{},{},{},{},{}\n".format('Value', 'Type', 'Tags', 'First seen', 'Last seen', "Analyzed"))

		self.output_json = open('{}/export_all.json'.format(self.engine.configuration['EXPORTS_DIR']), 'w+')
		self.output_json.write('[')
		for elt in self.model.elements.find():
			csv = elt.to_csv()
			self.output_csv.write("{}\n".format(elt.to_csv()))
			self.output_json.write("{}, ".format(elt.to_json()))
		
		self.output_csv.close()
		self.output_json.seek(-2, 2)  # nasty nasty hack
		self.output_json.write(']')
		self.output_json.close()

	def analyze(self, dict, mode):
		pass