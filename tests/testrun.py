import sys
from os import path
from datetime import timedelta
from mongoengine import connect

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.entities.malware import MalwareFamily, Malware
from core.indicators import Regex, Indicator
from core.database import Link
from core.entities import TTP, Exploit, ExploitKit
from core.observables import Observable
from core.observables import Tag
from core.exports import Export, ExportTemplate

## Clean slate
db = connect('yeti')
db.drop_database('yeti')

## Populate database with initial values
mailer = MalwareFamily("mailer").save()
banker = MalwareFamily("banker").save()
worm = MalwareFamily("worm").save()
ransomware = MalwareFamily("ransomware").save()
backdoor = MalwareFamily("backdoor").save()
stealer = MalwareFamily("stealer").save()
passwordstealer = MalwareFamily("passwordstealer").save()
rootkit = MalwareFamily("rootkit").save()
trojan = MalwareFamily("trojan").save()
dropper = MalwareFamily("dropper").save()

# Malware
e = ExploitKit(name="Angler").save()
e = ExploitKit(name="Neutrino").save()
e = Malware(name="Pony").save()
e.family = dropper
e.save()
e = ExploitKit(name="Magnitude").save()
e = ExploitKit(name="Fiesta").save()
e = ExploitKit(name="Nuclear").save()
e = Malware(name="Asprox").save()
e.family = dropper
e.save()
e = Malware(name="Neverquest").save()
e.family = trojan
e.save()
e = ExploitKit(name="Sweet Orange").save()
e = Malware(name="DarkComet").save()
e.family = trojan
e.save()
e = Malware(name="Upatre").save()
e.family = trojan
e.save()
e = ExploitKit(name="RIG").save()
e = Malware(name="CryptoWall").save()
e.family = ransomware
e.save()
e = Malware(name="Dridex").save()
e.family = trojan
e.save()
e = ExploitKit(name="BlackHole").save()
e = Malware(name="AlienSpy").save()
e.family = trojan
e.save()
e = Malware(name="Andromeda").save()
e.family = dropper
e.save()
e = Malware(name="Dyre").save()
e.family = trojan
e.save()
e = Exploit(name="CVE-2015-3113").save()
e = Malware(name="Teslacrypt").save()
e.family = ransomware
e.save()
e = Malware(name="Alphacrypt").save()
e.family = ransomware
e.save()
e = Malware(name="Locky").save()
e.family = ransomware
e.save()

t1 = Tag.get_or_create(name="zeus").add_produces(
    ["crimeware", "banker", "malware"])
t2 = Tag.get_or_create(name="banker").add_produces(["crimeware", "malware"])
t3 = Tag.get_or_create(name="c2")
t3.add_replaces(["c&c", "cc"])

Tag.get_or_create(name="crimeware").add_produces("malware")

et = ExportTemplate(name="Default")
et.template = "{{ obs.value }}\n"
et.save()

et = ExportTemplate(name="Bluecoat")
et.template = """define category cert_blocklist
{% for obs in elements %}{{ obs.value }}
{% endfor %}end
"""
et.save()
Export(
    name="TestExport",
    acts_on="Url",
    description="Test description",
    frequency=timedelta(hours=1),
    include_tags=[t1, t2],
    template=et).save()

url = Observable.add_text("hxxp://zeuscpanel.com/gate.php")
url.tag(["zeus", "banker", "cc", "c2"])
print url.tags

# print url.find_tags()

# import pdb; pdb.set_trace()

## Create some instances of malware & co
bartalex = Malware.get_or_create(name="Bartalex")
bartalex.family = MalwareFamily.objects.get(name="dropper")
bartalex.killchain = "3"
bartalex.tags = ["bartalex"]
bartalex.save()

dridex = Malware.get_or_create(name="Dridex")
dridex.aliases = ["Cridex", "Drixed"]
dridex.family = MalwareFamily.objects.get(name="banker")
dridex.killchain = "7"
dridex.tags = ['dridex']
dridex.save()

zeus = Malware.get_or_create(name="Zeus")
zeus.family = MalwareFamily.objects.get(name="banker")
zeus.killchain = "7"
zeus.tags = ['zeus']
zeus.save()

## Create initial intelligence

# Indicators
bartalex_callback = Regex(name="Bartalex callback", pattern="/mg.jpg$")
bartalex_callback.description = "Bartalex [stage2] callback (extracted from macros)"
bartalex_callback.diamond = "capability"
bartalex_callback.location = "network"
bartalex_callback.save()
bartalex_callback.action(bartalex, 'testrun', verb='indicates')

bartalex_callback2 = Regex(
    name="Bartalex callback", pattern="/[0-9a-z]{7,8}/[0-9a-z]{7,8}.exe$")
bartalex_callback2.description = "Bartalex [stage2] callback (extracted from macros)"
bartalex_callback2.diamond = "capability"
bartalex_callback2.location = "network"
bartalex_callback2.save()
bartalex_callback2.action(bartalex, 'testrun', verb="indicates")

bartalex_callback.action(dridex, 'testrun', verb="hosts")
bartalex_callback2.action(dridex, 'testrun', verb="hosts")

bartalex.action(dridex, 'testrun', verb="drops")

zeus_callback = Regex(name="Zeus C2 check-in", pattern="/gate.php$")
zeus_callback.description = "ZeuS post-infection callback"
zeus_callback.diamond = "capability"
zeus_callback.location = "network"
zeus_callback.save()
zeus_callback.action(zeus, 'testrun', verb='indicates')

# TTP

macrodoc = TTP(name="Macro-dropper")
macrodoc.killchain = "3"
macrodoc.description = "Macro-enabled MS Office document"
macrodoc.save()
bartalex.action(macrodoc, 'testrun', verb="leverages")
bartalex.action(macrodoc, 'testrun', verb="leverages")
bartalex.action(macrodoc, 'testrun', verb="leverages")

bartalex_callback.action(macrodoc, 'testrun', verb="seen in")
bartalex_callback2.action(macrodoc, 'testrun', verb="seen in")

payload_download = TTP(name="Payload retrieval (HTTP)")
payload_download.killchain = "3"
payload_download.description = "Payload is retreived from an external URL"
payload_download.save()
macrodoc.action(payload_download, 'testrun', verb="leverages")
bartalex_callback.action(payload_download, 'testrun', verb="indicates")
bartalex_callback2.action(payload_download, 'testrun', verb="indicates")

# add observables
o1 = Observable.add_text("85.214.71.240")
# o2 = Observable.add_text("http://soccersisters.net/mg.jpg")
o3 = Observable.add_text("http://agentseek.com/mg.jpg")
o4 = Observable.add_text("http://www.delianfoods.com/5t546523/lhf3f334f.exe")
o5 = Observable.add_text("http://sanoko.jp/5t546523/lhf3f334f.exe")
o6 = Observable.add_text("http://hrakrue-home.de/87yte55/6t45eyv.exe")
Link.connect(o6, bartalex_callback2)
Link.connect(o6, bartalex).add_history('testrun', 'Queries')
Link.connect(o6, dridex).add_history('testrun', 'Drops')
o7 = Observable.add_text("http://kdojinyhb.wz.cz/87yte55/6t45eyv.exe")
o8 = Observable.add_text("http://kdojinyhb.wz.cz/87yte55/6t45eyv.exe2")
o9 = Observable.add_text("http://zeuscpanel.com/gate.php")
o9.tag('zeus')

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
