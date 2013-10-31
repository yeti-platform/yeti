__author__ = 'pyt'
from celery import Celery
from celery.utils.log import get_task_logger

celery = Celery()
celery.config_from_object('celeryconfig')
logger = get_task_logger(__name__)
