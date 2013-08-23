import toolbox
import datetime
import pygeoip
from toolbox import debug_output


class Element(dict):

	default_fields = [('date_updated', 'Updated'), ('value', "Value"), ('type', "Type"), ('context', "Context")]	
	
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

	def is_recent(self):
		if 'date_created' not in self:
			return False
		else:
			return (self['date_created'] - datetime.datetime.now()) < datetime.timedelta(minutes=1)





class Evil(Element):
	display_fields = Element.default_fields + []
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
	display_fields = Element.default_fields + [
										('country', 'Country'),
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
	display_fields = Element.default_fields + [
							('scheme', 'Scheme'),
							('hostname', 'Hostname'),
							('path', 'Path'),
							]

	def __init__(self, url="", context=[]):
		super(Url, self).__init__()
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
		debug_output("(url analytics for %s)" % self['value'])

		new = []
		#link with hostname
		# host = toolbox.url_get_host(self['value'])
		# if host == None:
		# 	self['hostname'] = "No hostname"
		# else:
		# 	self['hostname'] = host

		# find path
		path, scheme, hostname = toolbox.split_url(self['value'])
		self['path'] = path
		self['scheme'] = scheme
		self['hostname'] = hostname

		if toolbox.is_ip(self['hostname']):
			new.append(('host', Ip(self['hostname'])))
		elif toolbox.is_hostname(self['hostname']):
			new.append(('host', Hostname(self['hostname'])))
		else:
			debug_output("No hostname found for %s" % self['value'], type='error')
			return

		self['last_analysis'] = datetime.datetime.utcnow()
		
		
		return new











class Ip(Element):

	display_fields = Element.default_fields + [
						('city', 'City'),
						('postal_code', "ZIP code"),
						('bgp', 'BGP'),
						('ISP', 'ISP'),
						# 'region_name',
						# 'area_code',
						('time_zone', 'TZ'),
						# 'dma_code',
						# ('metro_code', 'Metro code'),
						#'country_code3',
						#'country_name',
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
		debug_output( "(ip analytics for %s)" % self['value'])

		# get geolocation info
		try:
			gi = pygeoip.GeoIP('geoIP/GeoLiteCity.dat')
			geoinfo = gi.record_by_addr(self.value)
			for key in geoinfo:
				self[key] = geoinfo[key]
		except Exception, e:
			debug_output( "Could not get IP info for %s: %s" %(self.value, e), 'error')

		self['last_analysis'] = datetime.datetime.utcnow()

		return []










class Hostname(Element):
	
	display_fields = Element.default_fields + []

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

		debug_output( "(host analytics for %s)" % self.value)

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

DataTypes = {
	'url': Url,
	'ip': Ip,
	'hostname': Hostname,
	'as': As,
	'evil': Evil,
}
