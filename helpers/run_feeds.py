import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feed import Feed
import core.config.celeryimports

if __name__ == "__main__":

    if len(sys.argv) == 1:
        all_feeds = Feed.objects()
        print all_feeds
        exit()
    elif len(sys.argv) >= 2:
        all_feeds = [Feed.objects.get(name=sys.argv[1])]

    for n in all_feeds:
        print "Testing: {}".format(n)
        n.update()
