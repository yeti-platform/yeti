import urllib2
import datetime, re
from lxml import etree
import toolbox
from bson.objectid import ObjectId
from bson.json_util import dumps
from datatypes.element import Evil, Url
from feed import Feed



class ZeusTrackerBinaries(Feed):

    display = [ ("url", "URL"),
                         ("description", "Description"),
                         ("status", "Status"),
                         ("md5", "MD5"),
                         ("source", "Source"),
                         ("type", "Type"),
                         ("date_retreived", "Retrived")
                        ]

    def __init__(self, name):
        super(ZeusTrackerBinaries, self).__init__(name)
        self.normalized=[]
        self.parsed = None

    def get_info(self):
        try:
            feed = urllib2.urlopen("https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries")
            self.status = "OK"
        except Exception, e:
            self.status = "ERROR: " + e
            return False
        
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

        return True

    def analytics(self, analytics):

        self.elements_fetched = 0

        for entry in self.parsed:
            
            # Evil object
            evil = Evil()

            evil['feed'] = "ZeusTrackerBinaries"
            evil['url'] = toolbox.find_urls(entry['description'])[0]
            
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
            evil['context'] += ['zeus', 'malware']

            # date_retreived
            evil['date_retreived'] = datetime.datetime.utcnow()

            evil['value'] = "ZeuS bot"
            if md5:
                evil['value'] += " (MD5: %s)" % evil['md5']
            else:
                evil['value'] += " (URL: %s)" % evil['url']

            # commit to db
            evil = analytics.save_element(evil, ['ZeusTrackerBinaries'])

            # URL object
            url = Url(evil['url'], ['evil', 'ZeusTrackerBinaries'])

            # commit to db
            url = analytics.save_element(url)

            # connect url with malware
            analytics.data.connect(url, evil, ['hosting'])

            if evil.is_recent():
                self.elements_fetched += 1
            if url.is_recent():
                self.elements_fetched += 1


        analytics.process()
