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

import dns.resolver

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
          (?P<path>(\/[\S]*)?
            (\?[\S]*)?
            (\#[\S]*)?)
        )
    """

        #(((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>(((([\w\-]+\.)+)([a-zA-Z\-]{2,22}))|([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})))(\:[\d]{1,5})?(?P<path>(\/[\/\~\w\-_%\.\*\#\$]*)?(\?[\~\w\-_%\.&=\*\#\$]*)?(\#[\S]*)?))
ip_regex = r'([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})'

hostname_regex = r"((([\w\-]+\.)*)([\w\-]+))\.?"

email_regex = r"([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?"

hash_regex = r"([a-fA-F0-9]{32,64})"


tlds = ['abb', 'abbott', 'abogado', 'ac', 'academy', 'accenture', 'accountant', 'accountants', 'active', 'actor', 'ad', 'ads', 'adult', 'ae', 'aero', 'af', 'afl', 'ag', 'agency', 'ai', 'aig', 'airforce', 'al', 'allfinanz', 'alsace', 'am', 'amsterdam', 'an', 'android', 'ao', 'apartments', 'aq', 'aquarelle', 'ar', 'archi', 'army', 'arpa', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'auction', 'audio', 'auto', 'autos', 'aw', 'ax', 'axa', 'az', 'azure', 'ba', 'band', 'bank', 'bar', 'barclaycard', 'barclays', 'bargains', 'bauhaus', 'bayern', 'bb', 'bbc', 'bbva', 'bd', 'be', 'beer', 'berlin', 'best', 'bf', 'bg', 'bh', 'bi', 'bible', 'bid', 'bike', 'bingo', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'bloomberg', 'blue', 'bm', 'bmw', 'bn', 'bnpparibas', 'bo', 'boats', 'bond', 'boo', 'boutique', 'br', 'bridgestone', 'broker', 'brother', 'brussels', 'bs', 'bt', 'budapest', 'build', 'builders', 'business', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'cafe', 'cal', 'camera', 'camp', 'cancerresearch', 'canon', 'capetown', 'capital', 'caravan', 'cards', 'care', 'career', 'careers', 'cars', 'cartier', 'casa', 'cash', 'casino', 'cat', 'catering', 'cbn', 'cc', 'cd', 'center', 'ceo', 'cern', 'cf', 'cfa', 'cfd', 'cg', 'ch', 'channel', 'chat', 'cheap', 'chloe', 'christmas', 'chrome', 'church', 'ci', 'cisco', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'click', 'clinic', 'clothing', 'club', 'cm', 'cn', 'co', 'coach', 'codes', 'coffee', 'college', 'cologne', 'com', 'community', 'company', 'computer', 'condos', 'construction', 'consulting', 'contractors', 'cooking', 'cool', 'coop', 'corsica', 'country', 'coupons', 'courses', 'cr', 'credit', 'creditcard', 'cricket', 'crs', 'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dabur', 'dad', 'dance', 'date', 'dating', 'datsun', 'day', 'dclk', 'de', 'deals', 'degree', 'delivery', 'democrat', 'dental', 'dentist', 'desi', 'design', 'dev', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'dog', 'doha', 'domains', 'doosan', 'download', 'durban', 'dvag', 'dz', 'earth', 'eat', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'epson', 'equipment', 'er', 'erni', 'es', 'esq', 'estate', 'et', 'eu', 'eurovision', 'eus', 'events', 'everbank', 'exchange', 'expert', 'exposed', 'express', 'fail', 'faith', 'fan', 'fans', 'farm', 'fashion', 'feedback', 'fi', 'film', 'finance', 'financial', 'firmdale', 'fish', 'fishing', 'fit', 'fitness', 'fj', 'fk', 'flights', 'florist', 'flowers', 'flsmidth', 'fly', 'fm', 'fo', 'foo', 'football', 'forex', 'forsale', 'foundation', 'fr', 'frl', 'frogans', 'fund', 'furniture', 'futbol', 'fyi', 'ga', 'gal', 'gallery', 'garden', 'gb', 'gbiz', 'gd', 'gdn', 'ge', 'gent', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift', 'gifts', 'gives', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmo', 'gmx', 'gn', 'gold', 'goldpoint', 'golf', 'goo', 'goog', 'google', 'gop', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gratis', 'green', 'gripe', 'gs', 'gt', 'gu', 'guge', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hamburg', 'hangout', 'haus', 'healthcare', 'help', 'here', 'hermes', 'hiphop', 'hitachi', 'hiv', 'hk', 'hm', 'hn', 'hockey', 'holdings', 'holiday', 'homedepot', 'homes', 'honda', 'horse', 'host', 'hosting', 'house', 'how', 'hr', 'ht', 'hu', 'ibm', 'icbc', 'icu', 'id', 'ie', 'ifm', 'il', 'im', 'immo', 'immobilien', 'in', 'industries', 'infiniti', 'info', 'ing', 'ink', 'institute', 'insure', 'int', 'international', 'investments', 'io', 'iq', 'ir', 'irish', 'is', 'it', 'iwc', 'java', 'jcb', 'je', 'jetzt', 'jewelry', 'jll', 'jm', 'jo', 'jobs', 'joburg', 'jp', 'juegos', 'kaufen', 'kddi', 'ke', 'kg', 'kh', 'ki', 'kim', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'komatsu', 'kp', 'kr', 'krd', 'kred', 'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'land', 'lat', 'latrobe', 'lawyer', 'lb', 'lc', 'lds', 'lease', 'leclerc', 'legal', 'lgbt', 'li', 'liaison', 'lidl', 'life', 'lighting', 'limited', 'limo', 'link', 'lk', 'loan', 'loans', 'lol', 'london', 'lotte', 'lotto', 'love', 'lr', 'ls', 'lt', 'ltda', 'lu', 'lupin', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid', 'maif', 'maison', 'management', 'mango', 'market', 'marketing', 'markets', 'marriott', 'mba', 'mc', 'md', 'me', 'media', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu', 'mg', 'mh', 'miami', 'mil', 'mini', 'mk', 'ml', 'mm', 'mma', 'mn', 'mo', 'mobi', 'moda', 'moe', 'monash', 'money', 'montblanc', 'mormon', 'mortgage', 'moscow', 'motorcycles', 'mov', 'movie', 'mp', 'mq', 'mr', 'ms', 'mt', 'mtn', 'mtpc', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nadex', 'nagoya', 'name', 'navy', 'nc', 'ne', 'nec', 'net', 'network', 'neustar', 'new', 'news', 'nexus', 'nf', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'ninja', 'nissan', 'nl', 'no', 'np', 'nr', 'nra', 'nrw', 'ntt', 'nu', 'nyc', 'nz', 'okinawa', 'om', 'one', 'ong', 'onl', 'online', 'ooo', 'oracle', 'org', 'organic', 'osaka', 'otsuka', 'ovh', 'pa', 'page', 'panerai', 'paris', 'partners', 'parts', 'party', 'pe', 'pf', 'pg', 'ph', 'pharmacy', 'philips', 'photo', 'photography', 'photos', 'physio', 'piaget', 'pics', 'pictet', 'pictures', 'pink', 'pizza', 'pk', 'pl', 'place', 'plumbing', 'plus', 'pm', 'pn', 'pohl', 'poker', 'porn', 'post', 'pr', 'praxi', 'press', 'pro', 'prod', 'productions', 'prof', 'properties', 'property', 'ps', 'pt', 'pub', 'pw', 'py', 'qa', 'qpon', 'quebec', 'racing', 're', 'realtor', 'recipes', 'red', 'redstone', 'rehab', 'reise', 'reisen', 'reit', 'ren', 'rent', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review', 'reviews', 'rich', 'rio', 'rip', 'ro', 'rocks', 'rodeo', 'rs', 'rsvp', 'ru', 'ruhr', 'run', 'rw', 'ryukyu', 'sa', 'saarland', 'sale', 'samsung', 'sandvik', 'sandvikcoromant', 'sap', 'sarl', 'saxo', 'sb', 'sc', 'sca', 'scb', 'schmidt', 'scholarships', 'school', 'schule', 'schwarz', 'science', 'scot', 'sd', 'se', 'seat', 'sener', 'services', 'sew', 'sex', 'sexy', 'sg', 'sh', 'shiksha', 'shoes', 'show', 'shriram', 'si', 'singles', 'site', 'sj', 'sk', 'ski', 'sky', 'sl', 'sm', 'sn', 'sncf', 'so', 'soccer', 'social', 'software', 'sohu', 'solar', 'solutions', 'sony', 'soy', 'space', 'spiegel', 'spreadbetting', 'sr', 'st', 'study', 'style', 'su', 'sucks', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'swiss', 'sx', 'sy', 'sydney', 'systems', 'sz', 'taipei', 'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'td', 'team', 'tech', 'technology', 'tel', 'temasek', 'tennis', 'tf', 'tg', 'th', 'thd', 'theater', 'tickets', 'tienda', 'tips', 'tires', 'tirol', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'top', 'toray', 'toshiba', 'tours', 'town', 'toys', 'tr', 'trade', 'trading', 'training', 'travel', 'trust', 'tt', 'tui', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'university', 'uno', 'uol', 'us', 'uy', 'uz', 'va', 'vacations', 'vc', 've', 'vegas', 'ventures', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video', 'villas', 'vision', 'vlaanderen', 'vn', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'vu', 'wales', 'walter', 'wang', 'watch', 'webcam', 'website', 'wed', 'wedding', 'weir', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'win', 'wme', 'work', 'works', 'world', 'ws', 'wtc', 'wtf', 'xbox', 'xerox', 'xin', 'xn--1qqw23a', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c', 'xn--45q11c', 'xn--4gbrim', 'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--90ais', 'xn--9et52u', 'xn--b4w605ferd', 'xn--c1avg', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t', 'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--estv75g', 'xn--fiq228c5hs', 'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c', 'xn--gecrj9c', 'xn--h2brj9c', 'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1amh', 'xn--j6w193g', 'xn--kcrx77d1x4a', 'xn--kprw13d', 'xn--kpry57d', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd', 'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar', 'xn--mgbpl2fh', 'xn--mgbx4cd0ab', 'xn--mxtq1m', 'xn--ngbc5azd', 'xn--node', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--p1acf', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--qcka1pmc', 'xn--rhqv96g', 'xn--s9brj9c', 'xn--ses554g', 'xn--unup4y', 'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--vuq861b', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yandex', 'ye', 'yodobashi', 'yoga', 'yokohama', 'youtube', 'yt', 'za', 'zip', 'zm', 'zone', 'zuerich', 'zw']
# taken from http://data.iana.org/TLD/tlds-alpha-by-domain.txt

def list_to_str(obj):
    if isinstance(obj, list):
        return ", ".join([list_to_str(e) for e in obj])
    elif isinstance(obj, unicode):
        return obj
    else:
        return str(obj)


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
    if ip:
        match = re.match("^"+ip_regex+"$", ip)
        if match:
            return match.group(1)
    else:
        return False
    # ip = find_ips(ip)
    # if len(ip) > 0:
    #     return ip[0]
    # else:
    #     return None


def is_hostname(hostname):
    if hostname:
        match = re.match("^"+hostname_regex+"$", hostname)
        if match:
            return match.group(1)
    else:
        return False

    # hostname = find_hostnames(hostname)
    # if len(hostname) > 0:
    #     return string.lower(hostname[0])
    # else:
    #     return None

def is_subdomain(hostname):
    if hostname:
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

def dns_get_records(hostname, records=['A', 'NS', 'CNAME', 'MX']):
    records = {key: [] for key in records}

    if 'A' in records:
        try:
            results = dns.resolver.query(hostname, 'A')
            for r in results:
                records['A'].append(r.address)
        except Exception, e:
            debug_output("An error occured while resolving {} -> A: {}".format(hostname, e), type='error')

    if 'NS' in records:
        try:
            results = dns.resolver.query(hostname, 'NS')
            for r in results:
                tgt = r.target.to_text()
                if tgt[-1] == '.': tgt = tgt[:-1]
                records['NS'].append(tgt)
        except Exception, e:
            debug_output("An error occured while resolving {} -> NS: {}".format(hostname, e), type='error')

    if 'CNAME' in records:
        try:
            results = dns.resolver.query(hostname, 'CNAME')
            for r in results:
                tgt = r.target.to_text()
                if tgt[-1] == '.': tgt = tgt[:-1]
                records['CNAME'].append(tgt)
        except Exception, e:
            debug_output("An error occured while resolving {} -> CNAME: {}".format(hostname, e), type='error')

    if 'MX' in records:
        try:
            results = dns.resolver.query(hostname, 'MX')
            for r in results:
                mx = r.exchange.to_text()
                if mx[-1] == '.': mx = mx[:-1]
                records['MX'].append(mx)
        except Exception, e:
            debug_output("An error occured while resolving {} -> MX: {}".format(hostname, e), type='error')

    return records


def dns_dig_records(hostname):
    _dig = ""

    try:
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'A'])
    except CalledProcessError, e:
        pass

    try:
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'NS'])
    except CalledProcessError, e:
        pass

    try:
        _dig += check_output(['dig', hostname, '+noall', '+answer', 'CNAME'])
    except CalledProcessError, e:
        pass

    # _dig += check_output(['dig', hostname, '+noall', '+answer', 'MX'])

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

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception, e:
        host = None
    return host

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
    msg = ""
    if type == 'debug':
        msg = bcolors.DEBUG + '[DEBUG]'
    elif type == 'model':
        msg = bcolors.DATA + '[DATA]'
    elif type == 'analytics':
        msg = bcolors.ANALYTICS + '[ANALYTICS]'
    elif type == 'error':
        msg = bcolors.ERROR + '[ERROR]'
    elif type == 'info':
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
