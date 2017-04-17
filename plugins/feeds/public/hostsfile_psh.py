from datetime import datetime, timedelta
import logging

from core.observables import Hostname
from core.feed import Feed
from core.errors import ObservableValidationError

class HostsFilePSH(Feed):
	default_values = {
		'frequency': timedelta(hours=4),
		'source': 'https://hosts-file.net/psh.txt',
		'name': 'HostsFilePSH',
		'description': 'Domains associated to phishing attempts.'

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

			hostname = str(parts[1]).strip()
			context = {
				'source': self.name
			}
			
			try:
				host = Hostname.get_or_create(value=hostname)
				host.add_context(context)
				host.add_source('feed')
				host.tag(['phishing', 'blocklist'])
			except ObservableValidationError as e:
				logging.error(e)
		except Exception as e:
			logging.debug(e)


     
