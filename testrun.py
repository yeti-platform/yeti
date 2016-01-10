from datetime import timedelta

from mongoengine import connect

from core.entities.malware import MalwareFamily, Malware
from core.indicators import Regex, Indicator
from core.database import Link
from core.entities import TTP
from core.observables import Observable
from core.observables import Tag
from core.export import Export

## Clean slate
db = connect('yeti')
db.drop_database('yeti')

## Populate database with initial values
MalwareFamily("mailer").save()
MalwareFamily("banker").save()
MalwareFamily("worm").save()
MalwareFamily("ransomware").save()
MalwareFamily("backdoor").save()
MalwareFamily("stealer").save()
MalwareFamily("passwordstealer").save()
MalwareFamily("rootkit").save()
MalwareFamily("trojan").save()
MalwareFamily("dropper").save()


t1 = Tag.get_or_create(name="zeus").add_produces(["crimeware", "banker", "malware"])
t2 = Tag.get_or_create(name="banker").add_produces(["crimeware", "malware"])
t3 = Tag.get_or_create(name="c2")
t3.add_replaces(["c&c", "cc"])

Tag.get_or_create(name="crimeware").add_produces("malware")

Export(name="TestExport", description="Test description", frequency=timedelta(hours=1), include_tags=[t1, t2]).save()


url = Observable.add_text("hxxp://zeuscpanel.com/gate.php")
url.tag(["zeus", "banker", "cc", "c2"])
print url.tags

# print url.find_tags()

# import pdb; pdb.set_trace()



## Create some instances of malware & co
bartalex = Malware.get_or_create(name="Bartalex")
bartalex.family = MalwareFamily.objects.get(name="dropper")
bartalex.killchain = "delivery"
bartalex.save()

dridex = Malware.get_or_create(name="Dridex")
dridex.aliases = ["Cridex", "Drixed"]
dridex.family = MalwareFamily.objects.get(name="banker")
dridex.killchain = "objectives"
dridex.save()

## Create initial intelligence

# Indicators
bartalex_callback = Regex(name="Bartalex callback")
bartalex_callback.pattern = "/mg.jpg$"
bartalex_callback.description = "Bartalex [stage2] callback (extracted from macros)"
bartalex_callback.diamond = "Capability"
bartalex_callback.location = "network"
bartalex_callback.save()
bartalex_callback.action('indicates', bartalex, description="Bartalex payload URL (Dridex)")

bartalex_callback2 = Regex(name="Bartalex callback")
bartalex_callback2.pattern = "/[0-9a-z]{7,8}/[0-9a-z]{7,8}.exe$"
bartalex_callback2.description = "Bartalex [stage2] callback (extracted from macros)"
bartalex_callback2.diamond = "Capability"
bartalex_callback2.location = "network"
bartalex_callback2.save()
bartalex_callback2.action("indicates", bartalex, description="Bartalex payload URL (Dridex)")

bartalex_callback.action("hosts", dridex, description="Hosting Dridex")
bartalex_callback2.action("hosts", dridex, description="Hosting Dridex")

bartalex.action("drops", dridex, description="Drops Dridex")

# TTP

macrodoc = TTP(name="Macro-dropper")
macrodoc.killchain = "delivery"
macrodoc.description = "Macro-enabled MS Office document"
macrodoc.save()
bartalex.action("leverages", macrodoc)
bartalex_callback.action("seen in", macrodoc)
bartalex_callback2.action("seen in", macrodoc)

payload_download = TTP(name="Payload retrieval (HTTP)")
payload_download.killchain = "delivery"
payload_download.description = "Payload is retreived from an external URL"
payload_download.save()
macrodoc.action("leverages", payload_download)
bartalex_callback.action("indicates", payload_download)
bartalex_callback2.action("indicates", payload_download)

# add observables
o1 = Observable.add_text("85.214.71.240")
# o2 = Observable.add_text("http://soccersisters.net/mg.jpg")
o3 = Observable.add_text("http://agentseek.com/mg.jpg")
o4 = Observable.add_text("http://www.delianfoods.com/5t546523/lhf3f334f.exe")
o5 = Observable.add_text("http://sanoko.jp/5t546523/lhf3f334f.exe")
o6 = Observable.add_text("http://hrakrue-home.de/87yte55/6t45eyv.exe")
o7 = Observable.add_text("http://kdojinyhb.wz.cz/87yte55/6t45eyv.exe")
o8 = Observable.add_text("http://kdojinyhb.wz.cz/87yte55/6t45eyv.exe2")

t1 = Observable.add_text("http://toto.com")
t2 = Observable.add_text("Http://tata.com")
t3 = Observable.add_text("hxxp://tomchop[.]me")
l = Link.connect(t1, t2)
print "Links", Link.objects(src=t1)
t2.delete()
print "Links", Link.objects(src=t1)

test = "http://soccersisters.net/mg.jpg"

for i in Indicator.objects():
    if i.match(test):
        for type, nodes in i.neighbors().items():
            print " {}".format(type)
            for l, node in nodes:
                print {"type": type, "link": l.info(), "node": node.info()}

print "Test with the following:"
print o3.value
print o7.value
print t1.value
