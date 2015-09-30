from celery import Celery

celery_app = Celery('malcom')

class CeleryConfig:
    BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IMPORTS = ('core.config.celeryimports', )
    CELERY_TIMEZONE = 'UTC'

celery_app.config_from_object(CeleryConfig)
