import logging
from datetime import timedelta

from core.feed import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


def strip(str):
	return str.strip()


class CyberSweatShopPortscanRamnodeIP(Feed):

	default_values = {
		"frequency": timedelta(minutes=60),
		"name": "CyberSweatShopPortscanRamnodeIP",
		"source": "https://cybersweat.shop/iprep/iprep_ramnode.txt",
		"description": "CyberSweatShop; IP addresses have been detected performing TCP SYN to 81.4.103.251 to a non-listening service or daemon",
	}

	def update(self):
		for line in self.update_csv(delimiter=';', quotechar='_'):
			self.analyze(line)

		self.source = self.default_values['source']

	def analyze(self, line):
		if not line or line[0].startswith("#"):
			return

		try:
			ip, last_seen, honeypot_history, honeypot_history_totals = tuple(map(strip, line))
			context = {
				"last_seen": last_seen,
				"honeypot_history": honeypot_history,
				"honeypot_history_totals": honeypot_history_totals,
				"source": self.name
			}

			try:
				ip = Ip.get_or_create(value=ip)
				ip.add_context(context)
		ip.add_source('feed')
		ip.tag(['blocklist', 'portscan', 'honeypot'])
			except ObservableValidationError as e:
				logging.error("Invalid line: {}\nLine: {}".format(e, line))

		except ValueError:
			logging.error("Error unpacking line: {}".format(line))
