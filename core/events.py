from celery import Celery

from core.config.config import yeti_config

event_app = Celery(
    "events",
    broker=f"redis://{yeti_config.get('redis', 'host')}/",
    worker_pool_restarts=True,
)


def publish_event(event: str):
    """Publishes an event to the event bus.

    Args:
        event: A string representing an event.
    """
    event_app.send_task(
        "core.taskscheduler.publish_event", args=[event], queue="events"
    )
    return
