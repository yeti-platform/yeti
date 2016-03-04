import sys

from core.feed import Feed, update_feed
from core.scheduling import Scheduler

if __name__ == '__main__':
    Scheduler()
    # feeds = {f.name: f for f in }
    for f in Feed.objects():
        print repr(f.name)

    if len(sys.argv) > 1:
        name = sys.argv[1]
        f = Feed.objects.get(name=name)
        update_feed(f.id)
