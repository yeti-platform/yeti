import sys
import logging
from os import path

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.feed import Feed, update_feed
from core.scheduling import Scheduler

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    Scheduler()

    if len(sys.argv) == 1:
        print "Re-run using a feed name as argument"
        for f in Feed.objects():
            print "  {}".format(f.name)

    if len(sys.argv) > 1:
        name = sys.argv[1]
        f = Feed.objects.get(name=name)
        print "Running {}...".format(f.name)
        if update_feed(f.id):
            print "{}: success!".format(f.name)
