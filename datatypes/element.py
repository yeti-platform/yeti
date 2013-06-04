import toolbox
import datetime
import pygeoip
from pyfaup.faup import Faup


class Element(dict):
	def __init__(self):
		self['context'] = []

	def to_dict(self):
		return self.__dict__

	def __getattr__(self, name):
		return self[name]

	def __setattr__(self, name, value):
		self[name] = value

	def upgrade_context(self, context):
		self['context'].extend(context)
		self['context'] = list(set(self['context']))


class As(Element):

	def __init__(self, _as="", context=[]):
		self['as'] = ""
		self['type'] = 'as'
		self['context'] = context

	@staticmethod
	def from_dict(d):
		_as = As()
		for key in d:
			_as[key] = d[key]
		return _as

	def analytics(self):
		return []

class Url(Element):

	def __init__(self, url="", context=[]):
		# check if url is valid
		if toolbox.is_url(url) != url:
			return None
		else:
			self['url'] = url
			self['context'] = context
			self['type'] = 'url'

	@staticmethod
	def from_dict(d):
		url = Url()
		for key in d:
			url[key] = d[key]
		return url 

	def analytics(self):
		print "(url analytics for %s)" % self['url']

		new = []
		# link with hostname
		self['hostname'] = toolbox.url_get_hostname(self['url'])

		if toolbox.is_ip(self['hostname']):
			new.append(('host', Ip(self['hostname'])))
		elif toolbox.is_hostname(self['hostname']):
			new.append(('host', Hostname(self['hostname'])))

		self['last_analysis'] = datetime.datetime.utcnow()
		
		
		return new


class Ip(Element):

	def __init__(self, ip="", context=[]):
		# check if url is valid
		if toolbox.is_ip(ip) != ip:
			return None
		else:
			self['ip'] = ip
			self['context'] = context
			self['type'] = 'ip'

	@staticmethod
	def from_dict(d):
		ip = Ip()
		for key in d:
			ip[key] = d[key]
		return ip
			

	def analytics(self):
		print "(ip analytics for %s)" % self['ip']

		# get geolocation info
		try:
			gi = pygeoip.GeoIP('geoIP/GeoLiteCity.dat')
			self['geoinfo'] = gi.record_by_addr(self.ip)
		except Exception, e:
			print "Could not get IP info for %s: %s" %(self.ip, e)

		self['last_analysis'] = datetime.datetime.utcnow()

		return []

class Hostname(Element):
	"""docstring for Hostname"""
	def __init__(self, hostname="", context=[]):
		if toolbox.is_hostname(hostname) == hostname:
			self['context'] = context
			self['hostname'] = toolbox.is_hostname(hostname)
			if self['hostname'][-1:] == ".":
				self['hostname'] = self['hostname'][:-1]
			self['type'] = 'hostname'
		else:
			return None

	@staticmethod
	def from_dict(d):
		h = Hostname()
		for key in d:
			h[key] = d[key]
		return h 

		
	def analytics(self):

		print "(host analytics for %s)" % self.hostname

		# this should get us a couple of IP addresses, or other hostnames
		self['dns_info'] = toolbox.dns_dig_records(self.hostname)
		
		new = []

		#get Whois

		self['whois'] = toolbox.whois(self['hostname'])


		# get DNS info
		for record in self.dns_info:
			if record in ['MX', 'A', 'NS', 'CNAME']:
				for entry in self['dns_info'][record]:
					art = toolbox.find_artifacts(entry) #do this
					for t in art:
						for findings in art[t]:
							if t == 'hostnames':
								new.append((record, Hostname(findings)))
							if t == 'urls':
								new.append((record, Url(findings)))
							if t == 'ips':
								new.append((record, Ip(findings)))

		# is _hostname a subdomain ?
		if len(self.hostname.split(".")) > 2:
			f = Faup()
			f.decode(self['hostname'])  
			domain = f.get()['domain']
			if domain.split(".")[0] in ['co','com']:
				domain = "".join(f.get()['host'].split('.')[:-2][0]) + "." + domain

			if domain != self['hostname'] and domain not in new:
				new.append(('domain', Hostname(domain)))

		self['last_analysis'] = datetime.datetime.utcnow()

		return new