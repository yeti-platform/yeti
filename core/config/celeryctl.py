from __future__ import unicode_literals

from celery import Celery
from core.config.config import yeti_config

celery_app = Celery('yeti')


class CeleryConfig:
    BROKER_URL = 'redis://{}:{}/{}'.format(yeti_config.redis.host, yeti_config.redis.port, yeti_config.redis.database)
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IMPORTS = ('core.config.celeryimports', 'core.analytics_tasks', 'core.exports.export', 'core.feed')
    CELERY_TIMEZONE = 'UTC'
    CELERYD_POOL_RESTARTS = True
    CELERY_ROUTES = {
        'core.analytics_tasks.single': {'queue': 'oneshot'},
        'core.feed.update_feed': {'queue': 'feeds'},
        'core.exports.export.execute_export': {'queue': 'exports'},
        'core.analytics_tasks.each': {'queue': 'analytics'},
        'core.analytics_tasks.schedule': {'queue': 'analytics'},
    }

celery_app.config_from_object(CeleryConfig)
