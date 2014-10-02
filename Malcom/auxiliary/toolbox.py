import socket, sys
import inspect
import urlparse
import re
import urllib2
import socket
import json
import datetime
import string
#from pyquery import PyQuery               # external 
#from lxml import etree
from dateutil.parser import parse
import logging
from subprocess import check_output, CalledProcessError, STDOUT
from bson.json_util import dumps

url_regex = r"""

        (
          ((?P<scheme>[\w]{2,9}):\/\/)?
          ([\S]*\:[\S]*\@)?
          (?P<hostname>(
                      ((([\w\-]+\.)+)
                      ([a-zA-Z]{2,6}))
                      |([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})
                      |([\w\-]+)
                      )
          )

          (\:[\d]{1,5})?
          (?P<path>(\/[\/\~\w\-_%\.\*\#\$]*)?
            (\?[\~\w\-_%\.&=\*\#\$/]*)?
            (\#[\S]*)?)
        )
    """

        #(((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>(((([\w\-]+\.)+)([a-zA-Z\-]{2,22}))|([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})))(\:[\d]{1,5})?(?P<path>(\/[\/\~\w\-_%\.\*\#\$]*)?(\?[\~\w\-_%\.&=\*\#\$]*)?(\#[\S]*)?))
ip_regex = r'([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})'

hostname_regex = r"((([\w\-]+\.)*)([\w\-]+))\.?"

email_regex = r"([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?"

hash_regex = r"([a-fA-F0-9]{32,64})"


tlds = ['ac', 'academy', 'accountants', 'active', 'actor', 'ad', 'ae', 'aero', 'af', 'ag', 'agency', 'ai', 'airforce', 'al', 'am', 'an', 'ao', 'aq', 'ar', 'archi', 'army', 'arpa', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'audio', 'autos', 'aw', 'ax', 'axa', 'az', 'ba', 'bar', 'bargains', 'bayern', 'bb', 'bd', 'be', 'beer', 'berlin', 'best', 'bf', 'bg', 'bh', 'bi', 'bid', 'bike', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'blue', 'bm', 'bmw', 'bn', 'bo', 'boutique', 'br', 'brussels', 'bs', 'bt', 'build', 'builders', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'camera', 'camp', 'cancerresearch', 'capetown', 'capital', 'cards', 'care', 'career', 'careers', 'cash', 'cat', 'catering', 'cc', 'cd', 'center', 'ceo', 'cf', 'cg', 'ch', 'cheap', 'christmas', 'church', 'ci', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'clinic', 'clothing', 'club', 'cm', 'cn', 'co', 'codes', 'coffee', 'college', 'cologne', 'com', 'community', 'company', 'computer', 'condos', 'construction', 'consulting', 'contractors', 'cooking', 'cool', 'coop', 'country', 'cr', 'credit', 'creditcard', 'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cz', 'dance', 'dating', 'de', 'deals', 'degree', 'democrat', 'dental', 'dentist', 'desi', 'diamonds', 'digital', 'direct', 'directory', 'discount', 'dj', 'dk', 'dm', 'dnp', 'do', 'domains', 'durban', 'dz', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'engineer', 'engineering', 'enterprises', 'equipment', 'er', 'es', 'estate', 'et', 'eu', 'eus', 'events', 'exchange', 'expert', 'exposed', 'fail', 'farm', 'feedback', 'fi', 'finance', 'financial', 'fish', 'fishing', 'fitness', 'fj', 'fk', 'flights', 'florist', 'fm', 'fo', 'foo', 'foundation', 'fr', 'frogans', 'fund', 'furniture', 'futbol', 'ga', 'gal', 'gallery', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gift', 'gives', 'gl', 'glass', 'global', 'globo', 'gm', 'gmo', 'gn', 'gop', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gratis', 'green', 'gripe', 'gs', 'gt', 'gu', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hamburg', 'haus', 'hiphop', 'hiv', 'hk', 'hm', 'hn', 'holdings', 'holiday', 'homes', 'horse', 'host', 'house', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'immobilien', 'in', 'industries', 'info', 'ink', 'institute', 'insure', 'int', 'international', 'investments', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jetzt', 'jm', 'jo', 'jobs', 'joburg', 'jp', 'juegos', 'kaufen', 'ke', 'kg', 'kh', 'ki', 'kim', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'kp', 'kr', 'kred', 'kw', 'ky', 'kz', 'la', 'land', 'lawyer', 'lb', 'lc', 'lease', 'li', 'life', 'lighting', 'limited', 'limo', 'link', 'lk', 'loans', 'london', 'lotto', 'lr', 'ls', 'lt', 'lu', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'maison', 'management', 'mango', 'market', 'marketing', 'mc', 'md', 'me', 'media', 'meet', 'melbourne', 'menu', 'mg', 'mh', 'miami', 'mil', 'mini', 'mk', 'ml', 'mm', 'mn', 'mo', 'mobi', 'moda', 'moe', 'monash', 'mortgage', 'moscow', 'motorcycles', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nagoya', 'name', 'navy', 'nc', 'ne', 'net', 'neustar', 'nf', 'ng', 'nhk', 'ni', 'ninja', 'nl', 'no', 'np', 'nr', 'nrw', 'nu', 'nyc', 'nz', 'okinawa', 'om', 'onl', 'org', 'organic', 'ovh', 'pa', 'paris', 'partners', 'parts', 'pe', 'pf', 'pg', 'ph', 'photo', 'photography', 'photos', 'physio', 'pics', 'pictures', 'pink', 'pk', 'pl', 'place', 'plumbing', 'pm', 'pn', 'post', 'pr', 'press', 'pro', 'productions', 'properties', 'ps', 'pt', 'pub', 'pw', 'py', 'qa', 'qpon', 'quebec', 're', 'recipes', 'red', 'rehab', 'reise', 'reisen', 'ren', 'rentals', 'repair', 'report', 'republican', 'rest', 'reviews', 'rich', 'rio', 'ro', 'rocks', 'rodeo', 'rs', 'ru', 'ruhr', 'rw', 'ryukyu', 'sa', 'saarland', 'sb', 'sc', 'scb', 'schmidt', 'schule', 'scot', 'sd', 'se', 'services', 'sexy', 'sg', 'sh', 'shiksha', 'shoes', 'si', 'singles', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'social', 'software', 'sohu', 'solar', 'solutions', 'soy', 'space', 'sr', 'st', 'su', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'sx', 'sy', 'systems', 'sz', 'tattoo', 'tax', 'tc', 'td', 'technology', 'tel', 'tf', 'tg', 'th', 'tienda', 'tips', 'tirol', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'town', 'toys', 'tp', 'tr', 'trade', 'training', 'travel', 'tt', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'university', 'uno', 'us', 'uy', 'uz', 'va', 'vacations', 'vc', 've', 'vegas', 'ventures', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'villas', 'vision', 'vlaanderen', 'vn', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'vu', 'wang', 'watch', 'webcam', 'website', 'wed', 'wf', 'wien', 'wiki', 'works', 'ws', 'wtc', 'wtf', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c', 'xn--4gbrim', 'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--c1avg', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czru2d', 'xn--d1acj3b', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--gecrj9c', 'xn--h2brj9c', 'xn--i1b6b1a6a2e', 'xn--io0a7i', 'xn--j1amh', 'xn--j6w193g', 'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd', 'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar', 'xn--mgbx4cd0ab', 'xn--ngbc5azd', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--rhqv96g', 'xn--s9brj9c', 'xn--ses554g', 'xn--unup4y', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'ye', 'yokohama', 'yt', 'za', 'zm', 'zone', 'zw']
# taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt

def list_to_str(obj):
    if isinstance(obj, list):
        return ", ".join([list_to_str(e) for e in obj])
    else:
        return str(obj).decode('cp1252')


def send_msg(ws, msg, type='msg'):
    msg = {'type':type, 'msg': msg}
    try:
        ws.send(dumps(msg))
    except Exception, e:
        pass # debug_output("Could not send message: %s" % e)
        
    


def find_ips(data):
    ips = []
    for i in re.finditer(ip_regex,data):
        # sanitize IPs to avoid leading 0s
        ip = ".".join([str(int(dot)) for dot in i.group(1).split('.')])
        ips.append(ip)
    return ips

def find_urls(data):
    urls = []
    _re = re.compile(url_regex, re.VERBOSE)

    for i in re.finditer(_re,data):
        url = i.group(1)

        # if (len(h) > 0 or len(i) > 0) and url.find('/') != -1: # there's at least one IP or one domain name in the URL
        if url.find('/') != -1:
            urls.append(url)

    return urls

def find_hostnames(data):
    # sends back an array of hostnames
    hostnames = []
    for i in re.finditer(hostname_regex, data):
        h = string.lower(i.group(1))
        tld = h.split('.')[-1:][0]

        if tld in tlds:
            hostnames.append(h)

    return hostnames

def whois(data):
    
    try:
        response = check_output('whois %s' %data,
                shell=True,
                stderr=STDOUT)
        response = response.decode('cp1252').encode('utf-8')
    except Exception, e:
        response = "Whois resolution failed"
    
    return response


def find_emails(data):
    emails = []
    for i in re.finditer(email_regex,data):
        e = string.lower(i.group(1))
        tld = e.split('.')[-1:]
        emails.append(e)
    return emails

def find_hashes(data):
    hashes = []
    for i in re.finditer(hash_regex,data):
        hashes.append(string.lower(i.group(1)))
    return hashes

def find_artifacts(data):

    artifacts = {}

    as_list = []

    artifacts['urls'] = list(set(find_urls(data)))
    as_list += list(set(find_urls(data)))
    artifacts['hostnames'] = list(set(find_hostnames(data)))
    as_list += list(set(find_hostnames(data)))
    artifacts['hashes'] = list(set(find_hashes(data)))
    as_list += list(set(find_hashes(data)))
    artifacts['emails'] = list(set(find_emails(data)))
    as_list += list(set(find_emails(data)))
    artifacts['ips'] = list(set(find_ips(data)))
    as_list += list(set(find_ips(data)))

    return artifacts


def is_ip(ip):
    match = re.match("^"+ip_regex+"$", ip)
    if match:
        return match.group(1)
    else:
        return None
    # ip = find_ips(ip)
    # if len(ip) > 0:
    #     return ip[0]
    # else:
    #     return None


def is_hostname(hostname):
    match = re.match("^"+hostname_regex+"$", hostname)
    if match:
        return match.group(1)
    else:
        return None

    # hostname = find_hostnames(hostname)
    # if len(hostname) > 0:
    #     return string.lower(hostname[0])
    # else:
    #     return None

def is_subdomain(hostname):
    hostname = is_hostname(hostname)
    if hostname:
        tld = hostname.split('.')[-1:][0]
        if tld in tlds:
            tld = hostname.split('.')[-2:][0]
            if tld in tlds:
                domain = ".".join(hostname.split('.')[-3:])
                if domain == hostname:
                    return False
                else:
                    return domain
            else:
                domain = ".".join(hostname.split('.')[-2:])
                if domain == hostname:
                    return False
                else:
                    return domain
    else:
        return False


def is_url(url):
    match = re.match("^"+url_regex+"$", url, re.VERBOSE)
    if match:
        url = match.group(1)
        if url.find('/') != -1:
            return match.group(1)
    else:
        return None

    # url = find_urls(url)

    # if len(url) > 0:
    #     return url[0]
    # else:
    #     return None

def split_url(url):
    _re = re.compile(url_regex,re.VERBOSE)
    data = re.search(_re, url)
    if data:
        path = data.group('path')
        scheme = data.group('scheme')
        hostname = data.group('hostname')
        return (path, scheme, hostname)
    return None

def dns_dig_records(hostname):

    try:
        _dig = check_output(['dig', hostname, '+noall', '+answer', 'A'])
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'NS'])
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'MX'])
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'CNAME'])
    except CalledProcessError, e:
        _dig = e.output

    results = [r.groupdict() for r in re.finditer(re.escape(hostname)+'\..+\s+(?P<record_type>[A-Za-z]+)[\s]+([0-9]+ )?(?P<record>\S+)\n',_dig)]
    records = {}
    for r in results:
        if r['record_type'] in records:
            records[r['record_type']].append(r['record'])
        else:
            records[r['record_type']] = [r['record']]

    for r in records:
        records[r] = list(set(records[r]))
    return records

def dns_dig_reverse(ip):
    try:
        _dig = check_output(['dig', '-x', ip])
    except Exception, e:
        _dig = str(e)

    results = re.search('PTR\t+(?P<record>.+)', _dig)
    if results:
        hostname = is_hostname(results.group('record'))
    else:
        hostname = None

    return hostname



def url_get_host(url):
    hostname = split_url(url)[2]
    if hostname == "":
        return None
    else:
        return hostname
    

def url_check(url):
    try:
        result = urllib2.urlopen(url)
        return result.code
    except urllib2.HTTPError, e:
        return result.code
    except urllib2.URLError:
        return None

def get_net_info_shadowserver(ips):  
    #from shadowserver

    query = "begin origin\r\n"
    for ip in ips: query += str(ip['value']) + "\r\n"
    query +="end\r\n"

    #open('query.txt', 'w+').write(query)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("asn.shadowserver.org", 43))
    except Exception, e:
        debug_output("Failed to get AS data from asn.shadowserver.org: %s" % e)
        return None
    
    s.send(query)

    response = ''
    while True:
        data = s.recv(4096)
        response += data
        if not data: break
    s.close()

    parsed = parse_net_info_shadowserver(response)

    return parsed

    # Deal with responses like
    #
    #  IP            | AS  | BGP Prefix    | AS Name             | CC | Domain      | ISP 
    #  17.112.152.32 | 714 | 17.112.0.0/16 | APPLE-ENGINEERING   | US | APPLE.COM   | APPLE COMPUTER INC
    #

def parse_net_info_shadowserver(info):
    lines = info.split("\n")
    lines = lines[:-1]
    results = {}
    for line in lines:
        entry = {}
        columns = line.split("|")

        entry['ip'] = columns[0].lstrip().rstrip()
        entry['asn'] = columns[1].lstrip().rstrip()
        entry['bgp'] = columns[2].lstrip().rstrip()
        entry['name'] = columns[3].lstrip().rstrip().decode('latin-1')
        entry['country'] = columns[4].lstrip().rstrip()
        entry['domain'] = columns[5].lstrip().rstrip()
        entry['ISP'] = columns[6].lstrip().rstrip()
        entry['value'] = "%s (%s)" % (entry['name'], entry['asn'])

        results[entry['ip']] = entry

    return results

def get_net_info_cymru(ips):  
    #from cymru
    
    query = "begin\r\nverbose\r\n"
    for ip in ips: query += str(ip) + "\r\n"
    query +="end\r\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    debug_output("Connecting to whois.cymru.com")
    try:
        s.connect(("whois.cymru.com", 43))
    except Exception, e:
        debug_output("Failed to get AS data from whois.cymru.com: %s" % e)
        return None
    
    s.send(query)

    response = ''
    while True:
        data = s.recv(4096)
        response += data
        if not data: break
    s.close()

    parsed = parse_net_info(response)

    return parsed

    # Deal with responses like
    #
    # AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
    # 16276   | 213.251.173.198  | 213.251.128.0/18    | FR | ripencc  | 2004-05-18 | OVH OVH Systems
    #
def parse_net_info_cymru(info):
    lines = info.split("\n")
    lines = lines[1:-1]
    results = {}
    for line in lines:
        entry = {}
        columns = line.split("|")

        entry['value'] = columns[0].lstrip().rstrip()
        entry['bgp'] = columns[2].lstrip().rstrip()
        entry['country'] = columns[3].lstrip().rstrip()
        entry['registry'] = columns[4].lstrip().rstrip()
        entry['allocated'] = parse(columns[5].lstrip().rstrip())
        entry['as_name'] = columns[6].lstrip().rstrip()
        
        results[entry['value']] = entry

    return results

def debug_output(text, type='debug', n=True):
    if type == 'debug':
        msg = bcolors.DEBUG + '[DEBUG]'
    if type == 'model':
        msg = bcolors.DATA + '[DATA]'
    if type == 'analytics':
        msg = bcolors.ANALYTICS + '[ANALYTICS]'
    if type == 'error':
        msg = bcolors.ERROR + '[ERROR]'
    if type == 'info':
        msg = bcolors.INFO + '[INFO]'
    msg += bcolors.ENDC
    n = '\n' if n else ""

    try:
        sys.stdout.write(str("%s [%s] - %s%s" % (msg, datetime.datetime.now(), text, n)))
    except Exception, e:
        pass
    


class bcolors:
    DATA = '\033[95m'
    ANALYTICS = '\033[94m'
    DEBUG = '\033[92m'
    INFO = '\033[93m'
    ERROR = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.DATA = ''
        self.ANALYTICS = ''
        self.DEBUG = ''
        self.INFO = ''
        self.ERROR = ''
        self.ENDC = ''


if __name__ == "__main__":
    pass
        