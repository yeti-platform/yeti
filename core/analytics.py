from core.config.celeryctl import celery_app
from core.scheduling import ScheduleEntry

@celery_app.task
def schedule(name):
    print "Running analytics {}".format(name)

class Analytics(ScheduleEntry):
    """Base class for analytics. All analytics must inherit from this"""

    SCHEDULED_TASK = 'core.analytics.schedule'
