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
          (([\w]{2,9}):\/\/)?
          ([\S]*\:[\S]*\@)?
          (
            ((([\w\-]+\.)+)
            ([a-zA-Z]{2,6}))
            |([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})
          )

          (\:[\d]{1,5})?
          (\/[\/\w\-_%\.]+)?
          (\?[\w\-_%\.&=]+)?
          (\#[\S]+)?
        )
    """

tlds = [u'cx', u'cy', u'cz', u'ro', u'ke', u'kg', u'kh', u'ki', u'cr', u'cs', u'cu', u'cv', u'ch', u'ci', u'kr', u'ck', u'cl', u'cm', u'cn', u'co', u'rs', u'ca', u'kz', u'cc', u'cd', u'cf', u'cg', u'zw', u'iq', u'tk', u'za', u'info', u'nz', u'ua', u'name', u'ug', u'bz', u'by', u'uz', u'je', u'post', u'bs', u'br', u'bw', u'bv', u'jm', u'bt', u'bj', u'bi', u'bh', u'bo', u'bn', u'bm', u'bb', u'ba', u'jobs', u'bg', u'bf', u'be', u'bd', u'mo', u'kp', u'eh', u'eg', u'net', u'ec', u'tj', u'et', u'eu', u'er', u'travel', u'pm', u'pl', u'ee', u'in', u'io', u'il', u'im', u'pe', u'pg', u'kw', u'pa', u'id', u'ie', u'sk', u'py', u'yt', u'tg', u'ky', u'ir', u'is', u'pw', u'am', u'tz', u'it', u'lt', u'sd', u'pf', u'rw', u'ws', u'ru', u'tw', u'arpa', u'cat', u'pro', u'sh', u'si', u'sj', u'sc', u'sl', u'sm', u'sn', u'so', u'hm', u'sa', u'sb', u'hn', u'coop', u'se', u'hk', u'sg', u'hu', u'ht', u'sz', u'tv', u'hr', u'sr', u'ss', u'st', u'su', u'sv', u'sx', u'sy', u'mobi', u'wf', u'es', u'org', u'tel', u'ye', u'om', u'vu', u'priv', u'edu', u're', u'zm', u've', u'pn', u'vc', u'va', u'vn', u'tc', u'vi', u'ph', u'int', u'fo', u'fm', u'fk', u'fj', u'fi', u'fr', u'no', u'nl', u'SH', u'ni', u'ng', u'mz', u'ne', u'nc', u'biz', u'na', u'qa', u'com', u'nu', u'tc', u'nr', u'np', u'ac', u'test', u'af', u'ag', u'ad', u'ae', u'ai', u'an', u'ao', u'al', u'yu', u'ar', u'as', u'th', u'aq', u'aw', u'at', u'au', u'az', u'ax', u'pk', u'tl', u'mv', u'mw', u'mt', u'mu', u'mr', u'ms', u'mp', u'mq', u'tp', u'tn', u'km', u'tt', u'mx', u'my', u'mg', u'md', u'me', u'tm', u'mc', u'to', u'ma', u'mn', u'asia', u'ml', u'mm', u'mk', u'mh', u'tf', u'gt', u'dk', u'dj', u'dm', u'do', u'museum', u'kn', u'uy', u'de', u'dd', u'td', u'jp', u'dz', u'ps', u'nf', u'pt', u'pr', u'mil', u'ls', u'lr', u'lu', u'gr', u'lv', u'ly', u'jo', u'gov', u'vg', u'us', u'la', u'lc', u'lb', u'tm', u'li', u'lk', u'tr', u'gd', u'ge', u'gf', u'gg', u'ga', u'gb', u'gl', u'gm', u'gn', u'gh', u'gi', u'aero', u'gu', u'gw', u'gp', u'gq', u'xxx', u'gs', u'gy', u'la', u'uk']

def send_msg(ws, msg):
    msg = {'type':'msg', 'msg': msg}
    try:
        ws.send(dumps(msg))
    except Exception, e:
        debug_output("Could not send message: %s" % e)
    


def find_ips(data):
    ips = []
    for i in re.finditer("([\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3}\.[\d+]{1,3})",data):
        ips.append(i.group(1))
    return ips

def find_urls(data):
    urls = []
    _re = re.compile(url_regex,re.VERBOSE)

    for i in re.finditer(_re,data):
        url = i.group(1)

        h = find_hostnames(data)
        i = find_ips(data)
        
        if (len(h) > 0 or len(i) > 0) and url.find('/') != -1: # there's at least one IP or one hostname in the URL
            urls.append(url)

    return urls

def find_hostnames(data):
    # sends back an array of hostnames
    hostnames = []
    for i in re.finditer("((([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?", data):
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
    except Exception, e:
        response = "Whois resolution failed"
    
    return response


def find_emails(data):
    emails = []
    for i in re.finditer("([\w\-\.\_]+@(([\w\-]+\.)+)([a-zA-Z]{2,6}))\.?",data):
        e = string.lower(i.group(1))
        tld = e.split('.')[-1:]
        emails.append(e)
    return emails

def find_hashes(data):
    hashes = []
    for i in re.finditer("([a-fA-F0-9]{32,64})",data):
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
    ip = find_ips(ip)
    if len(ip) > 0:
        return ip[0]
    else:
        return None


def is_hostname(hostname):

    hostname = find_hostnames(hostname)
    if len(hostname) > 0:
        return string.lower(hostname[0])
    else:
        return None

def is_subdomain(hostname):
    hostname = find_hostnames(hostname)
    if len(hostname) > 0:
        print hostname
        hostname = hostname[0]

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

    url = find_urls(url)

    if len(url) > 0:
        return url[0]
    else:
        return None


def dns_dig_records(hostname):

    try:
        _dig = check_output(['dig','@8.8.8.8','ANY',hostname])
    except CalledProcessError, e:
        _dig = e.output

    results = [r.groupdict() for r in re.finditer(re.escape(hostname)+'\.\s+\d+\s+\w+\s+(?P<record_type>\w+)\s+(?P<record>.+)',_dig)]
    records = {}
    for r in results:
        if r['record_type'] in records:
            records[r['record_type']].append(r['record'])
        else:
            records[r['record_type']] = [r['record']]
    return records

def url_get_hostname(url):
    print url
    #hostnames = find_hostnames(url)
    #if len(hostnames) > 0:
    return find_hostnames(url)[0]

def url_check(url):
    try:
        result = urllib2.urlopen(url)
        return result.code
    except urllib2.HTTPError, e:
        return result.code
    except urllib2.URLError:
        return None

def get_net_info(ips):  
    #from cymru
    
    query = "begin\r\nverbose\r\n"
    for ip in ips: query += str(ip) + "\r\n"
    query +="end\r\n"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
def parse_net_info(info):
    lines = info.split("\n")
    lines = lines[1:-1]
    results = []
    for line in lines:
        entries = {}
        columns = line.split("|")

        entries['value'] = columns[0].lstrip().rstrip()
        entries['bgp'] = columns[2].lstrip().rstrip()
        entries['country'] = columns[3].lstrip().rstrip()
        entries['registry'] = columns[4].lstrip().rstrip()
        entries['allocated'] = parse(columns[5].lstrip().rstrip())
        entries['as_name'] = columns[6].lstrip().rstrip()
        
        
        results.append(entries)

    print results

    return results

def debug_output(text, n=True):
    sys.stderr.write(str(text))
    if n:
        sys.stderr.write('\n')        


# class XmlParser:      

#     _main_node = None
#     _children = None

#     def __init__(self, main_node, children):
#         self._main_node = main_node
#         self._children = children

#     def parse(self, data):
#         p = PyQuery(data)
#         items = p(self._main_node)
#         parsed = []

#         for item in items:
#             item = PyQuery(item)
#             line = {}
#             for child in self._children:
#                 line[child] = item.find(child).text()
#             parsed.append(line)
#         return parsed


if __name__ == "__main__":
    pass
        