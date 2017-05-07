from __future__ import unicode_literals

from celery import Celery

celery_app = Celery('yeti')


class CeleryConfig:
    # BROKER_URL = 'mongodb://localhost:27017/'
    BROKER_URL = 'redis://localhost:6379/0'
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
        'core.investigation.import_task': {'queue': 'oneshot'},
    }

celery_app.config_from_object(CeleryConfig)
