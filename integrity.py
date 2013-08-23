from analytics import Analytics
from toolbox import debug_output
a = Analytics()


# Check if there are elements which have no created date
nocreate = a.data.find({"date_created": None}).count()
type = "error" if nocreate > 0 else "debug"
debug_output("Elements without a date_created: {}".format(nocreate), type)

# Check if there are elements which have no updated date
noupdate = a.data.find({"date_updated": None}).count()
type = "error" if noupdate > 0 else "debug"
debug_output("Elements without a date_updated: {}".format(noupdate), type)

# Check if there are urls that don't have hostnames
nohostname = a.data.find({'type': 'url', 'hostname': None}).count()
type = "error" if nohostname > 0 else "debug"
debug_output("URLs without a hostname: {}".format(nohostname), type)

emptyhostname = a.data.find({'type': 'url', 'hostname': ""}).count()
type = "error" if emptyhostname > 0 else "debug"
debug_output("URLs without empty hostname: {}".format(emptyhostname), type)


