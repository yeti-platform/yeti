

from datetime import datetime, timedelta
import logging
import re

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError

class HostsFile_EMD(Feed):
	default_values = {
		'frequency': timedelta(hours=4),
		'source': 'https://hosts-file.net/emd.txt',
		'name': 'Hosts_File_EMD',
		'description': 'Sites engaged in malware distribution.'

	}


	regex = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+([^\n]+)$')

	def set(self, type, value):
		if type == 'default':
			self.default_values.update(value)

		if type == 'context':
			self.context.update(value)

		if type == 'tags':
			self.tags.append(value)

	def update(self):
		for line in self.update_lines():
			self.analyze(line)

	def analyze(self, line):
		try:
			match = line.match(regex)
			context = {
				'source': self.name
			}
			if match:
				try:
					host = Hostname.get_or_create(value=match.group(1))
					host.add_context(self.context)
					host.add_source('feed')
					host.tag(['malware', 'blocklist'])
				except ObservableValidationError as e:
					logging.error(e)
		except Exception as e:
			logging.debug(e)


     
