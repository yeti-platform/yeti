__author__ = 'pyt'
import sys
import os
from datetime import timedelta

sys.path.insert(0, os.getcwd())

CELERY_SEND_EVENTS = True
CELERY_TASK_PUBLISH_RETRY = True
BROKER_HEARTBEAT = 30
BROKER_CONNECTION_RETRY = True
BROKER_CONNECTION_MAX_RETRIES = 100
BROKER_CONNECTION_TIMEOUT = 4
CELERY_CREATE_MISSING_QUEUES = True

BROKER_URL = "amqp://guest:@127.0.0.1//"

CELERY_IMPORTS = ("Malcom.tasks.zeus",
                  "Malcom.tasks.spyeye",
                  "Malcom.tasks.mdl",
                  "Malcom.tasks.other",
                  "Malcom.tasks.scheduler"
)


CELERY_RESULT_BACKEND = "amqp://guest:@127.0.0.1//"
CELERY_TIMEZONE = 'UTC'

# CELERY_ROUTES = {
#     'CeleryPaste.tasks.couchdb_tasks': {'queue': 'db'},
#     'CeleryPaste.tasks.download_tasks': {'queue': 'download'},
#     'CeleryPaste.tasks.grabers_tasks': {'queue': 'grabers'},
#     'CeleryPaste.tasks.redis_tasks': {'queue': 'db'},
# }

CELERY_CREATE_MISSING_QUEUES = True

CELERYBEAT_SCHEDULE = {
    'runs-every-60-minute': {
        'task': 'Malcom.tasks.scheduler.worker',
        'schedule': timedelta(minutes=10)
    },
}