from core.feed import Feed
import core.config.celeryimports


if __name__ == '__main__':
    all_feeds = Feed.objects()
    for n in all_feeds:
        print "Testing: {}".format(n)
        n.update()
