from mongoengine import connect

from core.entities.malware import MalwareFamily, Malware
from core.indicators import Regex
from core.database import Link
from core.entities import TTP
from core.observables import Observable

## Clean slate
db = connect('malcom-v2')
db.drop_database('malcom-v2')

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
bartalex_callback.save()
bartalex.action('shows', bartalex_callback, description="Bartalex payload URL (Dridex)")

bartalex_callback2 = Regex(name="Bartalex callback")
bartalex_callback2.pattern = "/[0-9a-z]{7,8}/[0-9a-z]{7,8}.exe$"
bartalex_callback2.description = "Bartalex [stage2] callback (extracted from macros)"
bartalex_callback2.save()
bartalex.action("shows", bartalex_callback2, description="Bartalex payload URL (Dridex)")

dridex.action("is hosted", bartalex_callback, description="Hosting Dridex")
dridex.action("is hosted", bartalex_callback2, description="Hosting Dridex")

bartalex.action("drops", dridex, description="Drops Dridex")

# TTP

macrodoc = TTP(name="Macro-dropper")
macrodoc.killchain = "delivery"
macrodoc.description = "Macro-enabled MS Office document"
macrodoc.save()
bartalex.action("uses", macrodoc)

payload_download = TTP(name="Payload retrieval (HTTP)")
payload_download.killchain = "delivery"
payload_download.description = "Payload is retreived from an external URL"
payload_download.save()
macrodoc.action("uses", payload_download)

# add observables
o1 = Observable.add_text("85.214.71.240")
o2 = Observable.add_text("http://soccersisters.net/mg.jpg")
o3 = Observable.add_text("http://agentseek.com/mg.jpg")
o4 = Observable.add_text("http://www.delianfoods.com/5t546523/lhf3f334f.exe")
o5 = Observable.add_text("http://sanoko.jp/5t546523/lhf3f334f.exe")
o6 = Observable.add_text("http://hrakrue-home.de/87yte55/6t45eyv.exe")
o7 = Observable.add_text("http://kdojinyhb.wz.cz/87yte55/6t45eyv.exe")
