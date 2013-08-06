import toolbox
import datetime
import pygeoip

default_fields = [('value', "Value"), ('type', "Type"), ('context', "Context")]

class Element(dict):
	
	def __init__(self):
		self['context'] = []
		self['value'] = None
		self['type'] = None
		
	def to_dict(self):
		return self.__dict__

	def __getattr__(self, name):
		return self[name]

	def __setattr__(self, name, value):
		self[name] = value

	def upgrade_context(self, context):
		self['context'].extend(context)
		self['context'] = list(set(self['context']))

class Evil(Element):
	display_fields = default_fields + []
	def __init__(self, value='', type="malware", context=[]):
		super(Evil, self).__init__()
		self['value'] = value
		self['type'] = type
		self['context'] = context + ['evil']

	@staticmethod
	def from_dict(d):
		e = Evil()
		for key in d:
			e[key] = d[key]
		return e

	def analytics(self):
		self['last_analysis'] = datetime.datetime.utcnow()
		return []


class As(Element):
	display_fields = default_fields + [
										('country', 'CN'),
										('asn', 'ASN'),
										('domain', 'Domain'), 
										('ISP', 'ISP'),
										]
	def __init__(self, _as="", context=[]):
		super(As, self).__init__()
		self['value'] = _as
		self['type'] = 'as'
		self['context'] = context
		


	@staticmethod
	def from_dict(d):
		_as = As()
		for key in d:
			_as[key] = d[key]
		return _as

	def analytics(self):
		self['last_analysis'] = datetime.datetime.utcnow()

		return []


class Url(Element):
	display_fields = default_fields + [
							('hostname', 'Hostname'),
							]

	def __init__(self, url="", context=[]):
		super(Url, self).__init__()
		# check if url is valid
		if toolbox.is_url(url) != url:
			return None
		else:
			self['value'] = url
			self['context'] = context
			self['type'] = 'url'
			

	@staticmethod
	def from_dict(d):
		url = Url()
		for key in d:
			url[key] = d[key]
		return url 

	def analytics(self):
		print "(url analytics for %s)" % self['value']

		new = []
		# link with hostname
		host = toolbox.url_get_host(self['value'])
		if host == None:
			self['hostname'] = "No hostname"
		else:
			self['hostname'] = host

		if toolbox.is_ip(self['hostname']):
			new.append(('host', Ip(self['hostname'])))
		elif toolbox.is_hostname(self['hostname']):
			new.append(('host', Hostname(self['hostname'])))

		self['last_analysis'] = datetime.datetime.utcnow()
		
		
		return new


class Ip(Element):

	display_fields = default_fields + [
						('city', 'City'),
						('bgp', 'BGP prefix'),
						('ISP', 'AS'),
						# 'region_name',
						# 'area_code',
						('time_zone', 'TZ'),
						# 'dma_code',
						# ('metro_code', 'Metro code'),
						#'country_code3',
						#'country_name',
						('postal_code', "ZIP code"),
						#'longitude',
						('country_code', 'CN'),
						#'latitude',
						#'continent',
						#'date_created',
						#'date_updated',
						#'last_analysis',
						#'_id',
						#'type',
						]

	def __init__(self, ip="", context=[]):
		super(Ip, self).__init__()
		# check if url is valid
		if toolbox.is_ip(ip) != ip:
			return None
		else:
			self['value'] = ip
			self['context'] = context
			self['type'] = 'ip'
			

	@staticmethod
	def from_dict(d):
		ip = Ip()
		for key in d:
			ip[key] = d[key]
		return ip
			

	def analytics(self):
		print "(ip analytics for %s)" % self['value']

		# get geolocation info
		try:
			gi = pygeoip.GeoIP('geoIP/GeoLiteCity.dat')
			geoinfo = gi.record_by_addr(self.value)
			for key in geoinfo:
				self[key] = geoinfo[key]
		except Exception, e:
			print "Could not get IP info for %s: %s" %(self.value, e)

		self['last_analysis'] = datetime.datetime.utcnow()

		return []

class Hostname(Element):
	
	display_fields = default_fields + []

	def __init__(self, hostname="", context=[]):
		super(Hostname, self).__init__()
		if toolbox.is_hostname(hostname) == hostname:
			self['context'] = context
			self['value'] = toolbox.is_hostname(hostname)
			if self['value'][-1:] == ".":
				self['value'] = self['value'][:-1]
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

		print "(host analytics for %s)" % self.value

		# this should get us a couple of IP addresses, or other hostnames
		self['dns_info'] = toolbox.dns_dig_records(self.value)
		
		new = []

		#get Whois

		self['whois'] = toolbox.whois(self['value'])


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

		if len(self.value.split(".")) > 2:
			domain = toolbox.is_subdomain(self.value)
			if domain:
				new.append(('domain', Hostname(domain)))

		self['last_analysis'] = datetime.datetime.utcnow()

		return new