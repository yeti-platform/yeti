import urllib2
from lxml import etree
from toolbox import *
from bson.objectid import ObjectId
from bson.json_util import dumps


class ZeusTrackerBinaries:

    def __init__(self,analytics):
        self._normalized=[]
        self._parsed = None
        self._local_fields = ["url", "description", "status", "md5", "linkback", "type", "date_retreived"]

        self.get_info()
        self._normalize()

    def get_info(self):
        data = "\n".join(urllib2.urlopen("https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries").readlines())
        children = ["title", "link", "description", "guid"]
        main_node = "item"
        parser = XmlParser(main_node, children)
        self._parsed = parser.parse(data)
        return self._normalize()

    def _normalize(self):
        
        # Here we should create a DB object, put the values in it, and then save it to the DB
        if self._normalized:
            self._normalized = []

        for entry in self._parsed:
            normalized = {}
            
            # url
            # url = re.match("^([\S]+)",entry['title'])
            # if url != None: 
            #     normalized['url'] = url.group()
            # else: 
            #     normalized['url'] = "N/A"

            normalized['url'] = find_urls(entry['description'])[0]
            
            # description
            normalized['description'] = entry['link'] + " " + entry['description'] 

            # status
            if entry['description'].find("offline") != -1:
                normalized['status'] = "offline"
            else:
                normalized['status'] = "online"

            # md5
            md5 = re.search("MD5 hash: ([0-9a-f]{32,32})",entry['description'])
            if md5 != None:
                normalized['md5'] = md5.group(1)
            else:
                normalized['md5'] = "N/A"
            
            # linkback
            normalized['source'] = entry['guid']

            # type
            normalized['type'] = 'malware'

            # context
            normalized['context'] = ['zeus']

            # date_retreived
            normalized['date_retreived'] = datetime.datetime.utcnow()

            # priority
            normalized['score'] = 100

            self._normalized.append(normalized)

        return self._normalized

    def print_json(self, field=None):
        #json.dumps(self._normalized[1])
        for i in self._normalized:
            if field != None: 
                if field in i:
                    print json.dumps(i[field])
            else: print json.dumps(i)

    def get_json(self, field=None):
        return dumps(self._normalized)
        
    def print_normalized(self):
        for i in self._normalized:
            print i