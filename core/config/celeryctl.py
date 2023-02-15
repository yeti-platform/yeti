from __future__ import unicode_literals

from celery import Celery
from mongoengine import connect
from celery.signals import celeryd_init, worker_process_init

from core.config.config import yeti_config


celery_app = Celery("yeti")


class CeleryConfig:
    redis_scheme = "redis"
    if yeti_config.redis.tls:
        redis_scheme = redis_scheme + "s"

    broker_url = "{}://{}:{}/{}".format(
        redis_scheme,
        yeti_config.redis.host,
        yeti_config.redis.port,
        yeti_config.redis.database,
    )
    task_serializer = "json"
    accept_content = ["json"]
    imports = (
        "core.config.celeryimports",
        "core.analytics_tasks",
        "core.exports.export",
        "core.feed",
        "core.investigation",
        "plugins",
    )
    timezone = "UTC"
    worker_pool_restarts = True
    task_routes = {
        "core.analytics_tasks.single": {"queue": "oneshot"},
        "core.feed.update_feed": {"queue": "feeds"},
        "core.exports.export.execute_export": {"queue": "exports"},
        "core.analytics_tasks.each": {"queue": "analytics"},
        "core.analytics_tasks.schedule": {"queue": "analytics"},
        "core.investigation.import_task": {"queue": "oneshot"},
    }


celery_app.config_from_object(CeleryConfig)


@worker_process_init.connect
def connect_mongo(**kwargs):
    """Connect to mongo and load modules in each worker process."""
    from core.config import celeryimports
    from core.yeti_plugins import get_plugins

    is_tls = False
    if yeti_config.mongodb.tls:
        is_tls = True

    connect(
        yeti_config.mongodb.database,
        host=yeti_config.mongodb.host,
        port=yeti_config.mongodb.port,
        username=yeti_config.mongodb.username,
        password=yeti_config.mongodb.password,
        tls=is_tls,
        connect=False,
    )
    celeryimports.loaded_modules = get_plugins()


@celeryd_init.connect
def unlock_scheduled_entries(**kwargs):
    from core.analytics import ScheduledAnalytics
    from core.feed import Feed
    from core.exports.export import Export
    from core.yeti_plugins import get_plugin_classes

    # Make sure plugin classes are loaded
    get_plugin_classes()

    locked_entries = {
        "analytics": ScheduledAnalytics,
        "exports": Export,
        "feeds": Feed,
    }

    queues = kwargs["options"]["queues"].split(",")

    for queue in queues:
        if queue in locked_entries:
            locked_entries[queue].objects(lock=True).update(
                lock=False, status="Unlocked"
            )
