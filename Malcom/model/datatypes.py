<<<<<<< HEAD
import datetime, os, sys
from bson.json_util import dumps, loads
=======
import datetime
import os
>>>>>>> master

from Malcom.auxiliary.toolbox import debug_output
import Malcom.auxiliary.toolbox as toolbox

try:
    import geoip2.database
    file = os.path.abspath(__file__)
    current_path = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(current_path, '..', '/auxiliary/geoIP/GeoIP2-City.mmdb')
    geoip_reader = geoip2.database.Reader(current_path+'/../auxiliary/geoIP/GeoIP2-City.mmdb')
    geoip = True
except Exception, e:
<<<<<<< HEAD
	debug_output("Could not load GeoIP library - %s" % e, type='error')
	geoip = False

=======
    debug_output("Could not load GeoIP library - %s" % e, type='error')
    geoip = False
>>>>>>> master


class Element(dict):

    default_fields = [('value', "Value"), ('type', "Type"), ('tags', "Tags"), ('date_first_seen', 'First Seen'), ('date_last_seen', "Last Seen"), ('date_updated', 'Updated'), ('date_created', 'Created'), ('last_analysis', 'Analyzed')]

    def __init__(self):
        self['tags'] = []
        self['value'] = None
        self['type'] = None
        self['refresh_period'] = None
        self['evil'] = []

<<<<<<< HEAD
	def to_json(self):
		return dumps(self)

	def to_csv(self):
		value = self.get('value', "")
		_type = self.get('type', "")
		tags = u"|".join(self.get('tags', []))
		first_seen = self.get('date_first_seen', "")
		last_seen = self.get('date_last_seen', "")
		last_analysis = self.get('last_analysis', "")
		return u"{},{},{},{},{},{}".format(value, _type, tags, first_seen, last_seen, last_analysis)
=======
    def to_dict(self):
        return self.__dict__
>>>>>>> master

    def __getattr__(self, name):
        return self.get(name, None)

    def __setattr__(self, name, value):
        self[name] = value

    def __str__(self):
        return "[{} {} (tags: {})]".format(self.type, self.value, ",".join(self.tags))

    def upgrade_tags(self, tags):
        self['tags'].extend(tags)
        self['tags'] = list(set(self['tags']))

    # necessary for pickling
    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, d):
        self.__dict__.update(d)

    def add_evil(self, evil):
        if not self.get('evil'):
            self['evil'] = []

        if not evil.get('source'):
            raise ValueError("Evil info does not have a source:\n{}".format(evil))
        if not evil.get('description'):
            raise ValueError("Evil info does not have a description:\n{}".format(evil))

        if not evil.get('date_added'):
            evil['date_added'] = datetime.datetime.utcnow()

        for i, e in enumerate(self['evil'][:]):
            if e['source'] == evil['source']:
                self['evil'][i] = evil
                break
        else:
            self['evil'].append(evil)

    def seen(self, first=datetime.datetime.utcnow(), last=datetime.datetime.utcnow()):
        self['date_last_seen'] = last

        if self.get('date_first_seen') is None or self['date_first_seen'] > first:
            self['date_first_seen'] = first


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

    display_fields = Element.default_fields + [('link', 'Link'), ('guid', 'GUID'), ('description', 'Description')]
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

    element_fields = [
                        ('name', 'Name'),
                        ('ISP', 'ISP'),
                        #('domain', 'Domain'),
                        ('asn', 'ASN'),
                        ('country', 'Country'),
                        ]

    display_fields = Element.default_fields + element_fields
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
    element_fields = [
                        ('scheme', 'Scheme'),
                        ('hostname', 'Hostname'),
                        ('path', 'Path'),
                        ]
    display_fields = Element.default_fields + element_fields
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
        # link with hostname
        # host = toolbox.url_get_host(self['value'])
        # if host == None:
        #   self['hostname'] = "No hostname"
        # else:
        #   self['hostname'] = host

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

    element_fields = [
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

    display_fields = Element.default_fields + element_fields

    def __init__(self, ip="", tags=[]):
        super(Ip, self).__init__()
        self['value'] = ip
        self['tags'] = tags
        self['type'] = 'ip'
        self['refresh_period'] = Ip.default_refresh_period

    @staticmethod
    def from_dict(d):
        ip = Ip()
        for key in d:
            ip[key] = d[key]
        return ip

    def analytics(self):
        debug_output("(ip analytics for %s)" % self['value'])
        new = []

        # get reverse hostname
        hostname = toolbox.reverse_dns(self['value'])
        if hostname:
            if toolbox.is_hostname(hostname):
                new.append(('reverse', Hostname(hostname)))

        self.location_info()

        self['last_analysis'] = datetime.datetime.utcnow()
        self['next_analysis'] = self['last_analysis'] + datetime.timedelta(seconds=self['refresh_period'])

        return new

    def location_info(self):

        # get geolocation info (v2)
        if geoip:
            try:
                geoinfo = geoip_reader.city(self.value)

                self['city'] = geoinfo.city.name
                self['postal_code'] = geoinfo.postal.code
                self['time_zone'] = geoinfo.location.time_zone
                self['country_code'] = geoinfo.country.iso_code
                self['latitude'] = str(geoinfo.location.latitude)
                self['longitude'] = str(geoinfo.location.longitude)

            except Exception, e:
                debug_output("Could not get IP location info for %s: %s" % (self.value, e), 'error')


class Hostname(Element):

    default_refresh_period = 6*60*60  # 6 hours

    element_fields = []

    display_fields = Element.default_fields + element_fields

    def __init__(self, hostname="", tags=[]):
        super(Hostname, self).__init__()
        hostname = hostname.lower()
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

        debug_output("(host analytics for %s)" % self.value)

        new = []

        # only resolve A and CNAME records for subdomains
        if toolbox.is_subdomain(self.value):
            dns_info = toolbox.dns_get_records(self.value, ['A', 'CNAME'])
        else:
            dns_info = toolbox.dns_get_records(self.value)

        for rtype in dns_info:
                for entry in dns_info[rtype]:
                    art = toolbox.find_artifacts(entry)
                    for t in art:
                        for findings in art[t]:
                            if t == 'hostnames':
                                new.append((rtype, Hostname(findings)))
                            if t == 'urls':
                                new.append((rtype, Url(findings)))
                            if t == 'ips':
                                new.append((rtype, Ip(findings)))

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
