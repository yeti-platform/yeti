

from datetime import datetime, timedelta
import logging
import re

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError

class HostsFile_EXP(Feed):
	default_values = {
		'frequency': timedelta(hours=4),
		'source': 'https://hosts-file.net/exp.txt',
		'name': 'Hosts_File_EXP',
		'description': 'Sites engaged in the housing, development or distribution of exploits, including but not limited to exploitation of browser, software (inclusive of website software such as CMS), operating system exploits aswell as those engaged in exploits via social engineering.'

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
					host.tag(['malware', 'exploit', 'blocklist'])
				except ObservableValidationError as e:
					logging.error(e)
		except Exception as e:
			logging.debug(e)


     
