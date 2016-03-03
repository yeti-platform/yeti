from celery import Celery

celery_app = Celery('yeti')


class CeleryConfig:
    # BROKER_URL = 'mongodb://localhost:27017/'
    BROKER_URL = 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IMPORTS = ('core.config.celeryimports', 'core.analytics_tasks', 'core.exports.export', 'core.feed')
    CELERY_TIMEZONE = 'UTC'

    CELERY_ROUTES = {
        'core.analytics_tasks.single': {'queue': 'oneshot'},
        'core.feed.update_feed': {'queue': 'feeds'}
    }

celery_app.config_from_object(CeleryConfig)
