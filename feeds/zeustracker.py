import urllib2
from lxml import etree
from toolbox import *
from bson.objectid import ObjectId
from bson.json_util import dumps
from datatypes.element import Evil, Url


class ZeusTrackerBinaries:

    def __init__(self, analytics):
        self.normalized=[]
        self.parsed = None
        self.local_fields = ["url", "description", "status", "md5", "linkback", "type", "date_retreived"]
        self.a = analytics

    def get_info(self):
        feed = urllib2.urlopen("https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries")
        children = ["title", "link", "description", "guid"]
        main_node = "item"
        
        parsed = []

        tree = etree.parse(feed)
        for item in tree.findall("//%s"%main_node):
            dict = {}
            for field in children:
                dict[field] = item.findtext(field)
            parsed.append(dict)

        self.parsed = parsed

        return parsed

    def analytics(self):

        for entry in self.parsed:

            # Evil object

            evil = Evil()

            evil['url'] = find_urls(entry['description'])[0]
            
            # description
            evil['description'] = entry['link'] + " " + entry['description'] 

            # status
            if entry['description'].find("offline") != -1:
                evil['status'] = "offline"
            else:
                evil['status'] = "online"

            # md5 
            md5 = re.search("MD5 hash: (?P<md5>[0-9a-f]{32,32})",entry['description'])
            if md5 != None:
                evil['md5'] = md5.group('md5')
            else:
                evil['md5'] = "No MD5"
            
            # linkback
            evil['source'] = entry['guid']

            # type
            evil['type'] = 'evil'

            # context
            evil['context'] += ['zeus']

            # date_retreived
            evil['date_retreived'] = datetime.datetime.utcnow()

            evil['value'] = "ZeuS bot"
            if md5:
                evil['value'] += " (MD5: %s)" % evil['md5']
            else:
                evil['value'] += " (URL: %s)" % evil['url']

            # commit to db
            self.a.data.save(evil)

            # URL object

            url = Url(evil['url'], ['evil', 'zeus'])

            # commit to db
            self.a.data.save(url)

            # connect url with malware
            self.a.data.connect(url, evil, ['hosting'])

        self.a.process()

    def print_json(self, field=None):
        for i in self.normalized:
            if field != None: 
                if field in i:
                    print json.dumps(i[field])
            else: print json.dumps(i)

    def get_json(self, field=None):
        return dumps(self.normalized)
