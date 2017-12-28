from datetime import datetime, timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError

class BlocklistdePort22(Feed):
	default_values = {
		'frequency': timedelta(hours=1),
		'source': 'https://lists.blocklist.de/lists/22.txt',
		'name': 'BlocklistdePort22',
		'description': 'Blocklist.de IMAP IP blocklist: IPs performing attacks on port 22 (SSH)'

	}


	def update(self):
		for line in self.update_lines():
			self.analyze(line)

	def analyze(self, line):
		if line.startswith('#'):
			return

		try:
			line = line.strip()
			parts = line.split()

			ip = str(parts[0]).strip()
			context = {
				'source': self.name
			}

			try:
				ip = Ip.get_or_create(value=ip)
				ip.add_context(context)
				ip.add_source('feed')
				ip.tag(['blocklist', 'ssh'])
			except ObservableValidationError as e:
				logging.error(e)
		except Exception as e:
			logging.debug(e)
