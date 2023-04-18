#!/usr/bin/env python3
"""Unlocks locked SchedulEntries"""

from __future__ import print_function
import argparse
import sys
from os import path

from core.feed import Feed
from core.scheduling import Scheduler
from core.analytics import ScheduledAnalytics

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

parser = argparse.ArgumentParser(description="Unlock feed/analytics script")
parser.add_argument(
    "type",
    metavar="t",
    type=str,
    help='select "feed" or "analytics" script, answer all for all :)',
)
parser.add_argument(
    "name",
    metavar="n",
    type=str,
    help="select name of feed or analytics script, answer all for all :)",
)


def _unlock_all_feeds():
    for feed in Feed.objects(lock=True):
        feed.lock = False
        feed.save()
        print("{} unlocked".format(feed.name))


def _unlock_all_analytics():
    for script in ScheduledAnalytics.objects(lock=True):
        script.lock = False
        script.save()
        print("{} unlocked".format(script.name))


if __name__ == "__main__":
    Scheduler()
    args = parser.parse_args()
    print(args.type, args.name)
    if args.type == "all":
        _unlock_all_feeds()
        _unlock_all_analytics()
        print("All analytic scripts are unlocked!")
    elif args.type == "feed":
        if args.name == "all":
            _unlock_all_feeds()
        else:
            feed = Feed.objects.get(name=args.name)
            feed.lock = False
            feed.save()
            print("{} unlocked".format(feed.name))
    elif args.type == "analytics":
        if args.name == "all":
            _unlock_all_analytics()
        else:
            script = ScheduledAnalytics.objects.get(name=args.name)
            script.lock = False
            script.save()
            print("{} unlocked".format(script.name))
