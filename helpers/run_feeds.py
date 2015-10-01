import sys

from core.feed import Feed
import core.config.celeryimports


if __name__ == '__main__':

    if len(sys.argv) == 1:
        all_feeds = Feed.objects()
    elif len(sys.argv) >= 2:
        all_feeds = [Feed.objects.get(name=sys.argv[1])]

    print all_feeds
    for n in all_feeds:
        print "Testing: {}".format(n)
        n.update()
