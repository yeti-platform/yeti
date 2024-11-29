import logging
import threading
import time
from queue import Queue
from typing import ClassVar

import requests

from core import taskmanager
from core.config.config import yeti_config
from core.events.message import EventMessage, ObjectEvent, TagEvent
from core.schemas import task

metrics_queue = Queue()
import hashlib


class MetricsFlusher(threading.Thread):
    METRIC_ENDPOINT = "https://api.datadoghq.com/api/v2/series"

    def __init__(self, flush_interval: float, flush_count: int):
        """
        Initialize the MetricsFlusher.
        :param flush_interval: Interval in seconds between each flush.
        :param flush_count: Number of items to remove from the queue at each flush.
        """
        self._dd_api_key = yeti_config.get("datadog", "api_key")
        self._dd_app_key = yeti_config.get("datadog", "app_key")
        self._dd_env = yeti_config.get("datadog", "env", "dev")
        self._session = requests.Session()
        self._session.headers = {
            "DD-API-KEY": self._dd_api_key,
            "DD-APPLICATION-KEY": self._dd_app_key,
        }
        self._logger = logging.getLogger("FlushMetricsQueue")
        self._flush_interval = flush_interval
        self._flush_count = flush_count
        self._running = True

        super().__init__(daemon=True)

    def run(self):
        """
        Flush the queue at intervals.
        """
        while True:
            time.sleep(self._flush_interval)
            self._flush()

    def _flush(self):
        """
        Flush items from the queue. Removes up to `flush_count` items.
        """
        self._logger.debug(
            f"Flushing metrics queue {metrics_queue} (size:{metrics_queue.qsize()})"
        )
        timeseries = {}
        for _ in range(self._flush_count):
            if not metrics_queue.empty():
                key = hashlib.sha256()
                timestamp, metric, tags = metrics_queue.get()
                key.update(str(timestamp).encode())
                key.update(str(metric).encode())
                key.update(str(tags).encode())
                key = key.hexdigest()
                if key not in timeseries:
                    timeseries[key] = {
                        "metric": metric,
                        "type": 1,
                        "points": [{"timestamp": timestamp, "value": 0}],
                        "tags": tags,
                    }
                timeseries[key]["points"][0]["value"] += 1
            else:
                break
        if timeseries:
            payload = {"series": []}
            for key, serie in timeseries.items():
                payload["series"].append(serie)
            try:
                response = self._session.post(
                    MetricsFlusher.METRIC_ENDPOINT, json=payload
                )
            except Exception:
                self._logger.exception("Failed to send metrics to Datadog")
            if response.status_code == 202:
                self._logger.info("Successfully sent metrics to Datadog")
            else:
                self._logger.warning(
                    f"Failed to send metrics to Datadog: {response.reason}"
                )


class DatadogMetrics(task.EventTask):
    _defaults = {
        "name": "DatadogMetrics",
        "description": "Send events as Datadog metrics",
        "acts_on": "(new|update|delete)",
    }

    _metrics_flusher: ClassVar[MetricsFlusher] = None

    def __init__(self, **data):
        super().__init__(**data)

    def run(self, message: EventMessage) -> None:
        if DatadogMetrics._metrics_flusher is None:
            DatadogMetrics._metrics_flusher = MetricsFlusher(
                yeti_config.get("datadog", "flush_interval", 10),
                yeti_config.get("datadog", "flush_count", 1000),
            )
            DatadogMetrics._metrics_flusher.start()
        self._dd_env = yeti_config.get("datadog", "env", "dev")
        self._timestamp = int(message.timestamp.timestamp())
        if isinstance(message.event, ObjectEvent):
            self._send_object_serie(message.event)
        elif isinstance(message.event, TagEvent):
            self._send_tag_serie(message.event)
        return

    def _enqueue_serie(self, metric, tags):
        self.logger.debug(f"Enqueueing metric {metric} with tags {tags}")
        tags.append(f"env:{self._dd_env}")
        metrics_queue.put((self._timestamp, metric, tags))

    def _send_object_serie(self, event: ObjectEvent):
        type = event.yeti_object.root_type
        if hasattr(event.yeti_object, "type"):
            type += f".{event.yeti_object.type}"
        tags = [
            f"type:{type}",
            f"event:{event.type}",
        ]
        self._enqueue_serie("yeti.object", tags)

    def _send_tag_serie(self, event: TagEvent):
        type = event.tagged_object.root_type
        if hasattr(event.tagged_object, "type"):
            type += f".{event.tagged_object.type}"
        tags = [
            f"tag:{event.tag_object.name}",
            f"type:{type}",
            f"event:{event.type}",
        ]
        self._enqueue_serie("yeti.tagged", tags)


taskmanager.TaskManager.register_task(DatadogMetrics)
