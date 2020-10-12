"""Unlocks locked SchedulEntries"""

from __future__ import print_function
import logging
import sys
from os import path

from core.feed import Feed
from core.scheduling import Scheduler

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    Scheduler()

    if len(sys.argv) > 1:
        name = sys.argv[1]
        f = Feed.objects.get(name=name)
        print("Running {}...").format(f.name)
        f.lock = False
        f.save()
        print("{} unlocked".format(f.name))
