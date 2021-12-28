"""Run scheduled jobs."""
import sys
import logging
from os import path
from core.analytics import ScheduledAnalytics
from core.scheduling import Scheduler

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    Scheduler()

    if len(sys.argv) == 1:
        print("Re-run using a analytic name as argument")
        for f in ScheduledAnalytics.objects():
            print(f"   {f.name}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        f = ScheduledAnalytics.objects.get(name=name)
        print(f"Running {f.name}...")
        f.analyze_outdated()
