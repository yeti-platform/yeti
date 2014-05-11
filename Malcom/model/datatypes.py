
import datetime, os
try:
	import geoip2.database
	geoip = True
except Exception, e:
	print "Geoip2 database not found"
	geoip = False


import Malcom.auxiliary.toolbox as toolbox
from Malcom.auxiliary.toolbox import debug_output
import Malcom


class Element(dict):

	default_fields = [('value', "Value"), ('type', "Type"), ('tags', "Tags"), ('date_updated', 'Updated'), ('date_created', 'Created'), ('last_analysis', 'Analyzed') ]	
	
	def __init__(self):
		self['tags'] = []
		self['value'] = None
		self['type'] = None
		self['refresh_period'] = None
		# all elements have to be analysed at least once

		
	def to_dict(self):
		return self.__dict__

	def __getattr__(self, name):
		return self.get(name, None)

	def __setattr__(self, name, value):
		self[name] = value

	def upgrade_tags(self, tags):
		self['tags'].extend(tags)
		self['tags'] = list(set(self['tags']))

	# def is_recent(self):
	# 	if 'date_created' not in self:
	# 		return False
	# 	else:
	# 		return (self['date_created'] - datetime.datetime.now()) < datetime.timedelta(minutes=1)

	# necessary for pickling
	def __getstate__(self): return self.__dict__
	def __setstate__(self, d): self.__dict__.update(d)


class File(Element):
	
	display_fields = Element.default_fields + [('md5', "MD5"), ('file_type', "Type")]
	default_refresh_period = None
	
	def __init__(self, value='', type='file', tags=[]):
		super(File, self).__init__()
		self['value'] = value
		self['type'] = type
		self['tags'] = tags
		self['refresh_period'] = File.default_refresh_period

	@staticmethod
	def from_dict(d):
		f = File()
		for key in d:
			f[key] = d[key]
		return f

	def analytics(self):
		self['last_analysis'] = datetime.datetime.utcnow()
		# md5
		self['md5'] = ""
		self['file_type'] = "None"
		# analysis does not change with time
		self['next_analysis'] = None
		return []



class Evil(Element):
	
	display_fields = Element.default_fields + []
	default_refresh_period = None

	def __init__(self, value='', type="evil", tags=[]):
		super(Evil, self).__init__()
		self['value'] = value
		self['type'] = type
		self['tags'] = tags + ['evil']
		self['refresh_period'] = Evil.default_refresh_period

	@staticmethod
	def from_dict(d):
		e = Evil()
		for key in d:
			e[key] = d[key]
		return e

	def analytics(self):
		self['last_analysis'] = datetime.datetime.utcnow()
		
		# analysis does not change with time
		self['next_analysis'] = None
		return []


class As(Element):
	display_fields = Element.default_fields + [
										('name', 'Name'),
										('ISP', 'ISP'),
										#('domain', 'Domain'), 
										('asn', 'ASN'),
										('country', 'Country'),
										]
	default_refresh_period = None

	def __init__(self, _as="", tags=[]):
		super(As, self).__init__()
		self['value'] = _as
		self['type'] = 'as'
		self['tags'] = tags
		self['refresh_period'] = As.default_refresh_period



	@staticmethod
	def from_dict(d):
		_as = As()
		for key in d:
			_as[key] = d[key]
		return _as

	def analytics(self):
		self['last_analysis'] = datetime.datetime.utcnow()

		# analysis does not change with time
		self['next_analysis'] = None
		return []



class Url(Element):
	display_fields = Element.default_fields + [
							('scheme', 'Scheme'),
							('hostname', 'Hostname'),
							('path', 'Path'),
							]
	default_refresh_period = None

	def __init__(self, url="", tags=[]):
		super(Url, self).__init__()
		self['value'] = url
		self['tags'] = tags
		self['type'] = 'url'
		self['refresh_period'] = Url.default_refresh_period

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
			new.append(('host', Ip(toolbox.is_ip(self['hostname']))))
		elif toolbox.is_hostname(self['hostname']):
			new.append(('host', Hostname(toolbox.is_hostname(self['hostname']))))
		else:
			debug_output("No hostname found for %s" % self['value'], type='error')
			return []

		self['last_analysis'] = datetime.datetime.utcnow()

		# this information is constant and does not change through time
		# we'll have to change this when we check for URL availability
		self['next_analysis'] = None

		return new



class Ip(Element):
	
	default_refresh_period = 3*24*3600

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

	def __init__(self, ip="", tags=[]):
		super(Ip, self).__init__()
		self['value'] = ip
		self['tags'] = tags
		self['type'] = 'ip'
		# refresh IP geolocation every 72hours
		self['refresh_period'] = Ip.default_refresh_period
			

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
			file = os.path.abspath(__file__)
			if geoip:
				reader = geoip2.database.Reader(Malcom.config['BASE_PATH']+'/auxiliary/geoIP/GeoLite2-City.mmdb')
				geoinfo = reader.city(self.value)
				
				self['city'] = geoinfo.city.name
				self['postal_code'] = geoinfo.postal.code
				self['time_zone'] = geoinfo.location.time_zone
				self['country_code'] = geoinfo.country.iso_code
				self['latitude'] = str(geoinfo.location.latitude)
				self['longitude'] = str(geoinfo.location.longitude)

		except Exception, e:
			debug_output( "Could not get IP info for %s: %s" %(self.value, e), 'error')

		# get reverse hostname
		new = []
		hostname = toolbox.dns_dig_reverse(self['value'])
		
		if hostname:
			new.append(('reverse', Hostname(hostname)))

		self['last_analysis'] = datetime.datetime.utcnow()
		self['next_analysis'] = self['last_analysis'] + datetime.timedelta(seconds=self['refresh_period'])

		return new



class Hostname(Element):
	
	default_refresh_period = 6*3600
	display_fields = Element.default_fields + []

	def __init__(self, hostname="", tags=[]):
		super(Hostname, self).__init__()
		if toolbox.is_hostname(hostname) == hostname:
			self['tags'] = tags
			self['value'] = toolbox.is_hostname(hostname)
			if self['value'][-1:] == ".":
				self['value'] = self['value'][:-1]
			self['type'] = 'hostname'

			# refresh domains every 6 hours
			self['refresh_period'] = Hostname.default_refresh_period
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
		self['next_analysis'] = self['last_analysis'] + datetime.timedelta(seconds=self['refresh_period'])

		return new

DataTypes = {
	'url': Url,
	'ip': Ip,
	'hostname': Hostname,
	'as': As,
	'evil': Evil,
}
