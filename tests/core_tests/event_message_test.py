"""The strings that EventTask.acts_on patterns are matched against.

The events consumer rebuilds each event from the published JSON and runs every
enabled EventTask whose acts_on matches (core/events/consumers.py). Patterns are
written against enum values ("new", "analytics"), but on Python >= 3.11 an
f-string renders a (str, Enum) member as "EventType.new". None of these tests
needs ArangoDB or Redis.
"""

import datetime
import importlib
import json
import queue
import unittest
from unittest import mock

from core import taskmanager
from core.events import message
from core.schemas import dfiq, graph, observable, tag, task
from core.schemas.observables import container_image


def as_consumed(event):
    """Returns the event the consumer rebuilds from the published JSON."""
    published = message.EventMessage(event=event).model_dump_json()
    return message.EventMessage(**json.loads(published))


def import_event_plugin(name):
    """Imports a plugin without registering its tasks in the database.

    Plugins call TaskManager.register_task when imported, which reads and
    writes ArangoDB. These tests only need the classes.
    """
    with mock.patch.object(taskmanager.TaskManager, "register_task"):
        return importlib.import_module(name)


def dfiq_scenario():
    return dfiq.DFIQScenario(
        name="scenario", dfiq_version="1.1.0", description="d", dfiq_yaml="x"
    )


def dfiq_facet():
    return dfiq.DFIQFacet(
        name="facet",
        dfiq_version="1.1.0",
        description="d",
        dfiq_yaml="x",
        parent_ids=[],
    )


class EventStringTest(unittest.TestCase):
    def setUp(self) -> None:
        self.url = observable.Url(value="http://example.com/x")
        self.hostname = observable.Hostname(value="example.com")

    def link_event(self, source, target):
        now = datetime.datetime.now(datetime.timezone.utc)
        relationship = graph.Relationship(
            source="a/1",
            target="b/2",
            type="link",
            description="",
            created=now,
            modified=now,
        )
        return as_consumed(
            message.LinkEvent(
                type=message.EventType.new,
                source_object=source,
                target_object=target,
                relationship=relationship,
            )
        ).event

    def test_object_event_string(self) -> None:
        """The prefix is the event type's value, not "EventType.new"."""
        event = as_consumed(
            message.ObjectEvent(type=message.EventType.new, yeti_object=self.url)
        ).event
        self.assertEqual(event.event_message, "new:observable:url")

    def test_object_event_string_with_enum_object_type(self) -> None:
        """Tasks and DFIQ objects have enum-typed `type` fields, unlike the
        plain strings of other objects, so the suffix needs the value too."""
        cases = [
            (task.AnalyticsTask(name="analytics"), "update:task:analytics"),
            (dfiq_scenario(), "update:dfiq:scenario"),
        ]
        for yeti_object, expected in cases:
            with self.subTest(expected=expected):
                event = as_consumed(
                    message.ObjectEvent(
                        type=message.EventType.update, yeti_object=yeti_object
                    )
                ).event
                self.assertEqual(event.event_message, expected)

    def test_link_event_strings(self) -> None:
        event = self.link_event(self.url, self.hostname)
        self.assertEqual(event.link_source_event, "new:link:source:observable:url")
        self.assertEqual(event.link_target_event, "new:link:target:observable:hostname")

    def test_link_event_strings_with_enum_object_type(self) -> None:
        """DFIQ objects are linked to each other (DFIQBase.update_parents)."""
        event = self.link_event(dfiq_scenario(), dfiq_facet())
        self.assertEqual(event.link_source_event, "new:link:source:dfiq:scenario")
        self.assertEqual(event.link_target_event, "new:link:target:dfiq:facet")

    def test_tag_event_string(self) -> None:
        event = as_consumed(
            message.TagEvent(
                type=message.EventType.delete,
                tagged_object=self.url,
                tag_object=tag.Tag(name="malware"),
            )
        ).event
        self.assertEqual(event.tag_message, "delete:tagged:malware")


class ShippedEventTasksTest(unittest.TestCase):
    """The consumer runs a task when event.match(task.compiled_acts_on) is
    true. Every shipped pattern starts with the event type, so none of these
    tasks ran while the strings started with "EventType."."""

    def setUp(self) -> None:
        self.url = observable.Url(value="http://example.com/x")

    def acts_on(self, module, name):
        cls = getattr(import_event_plugin(module), name)
        # Built from _defaults, as TaskManager.register_task does.
        return cls(**cls._defaults).compiled_acts_on

    def test_hostname_extract(self) -> None:
        acts_on = self.acts_on("plugins.events.hostname_extract", "HostnameExtract")
        for event_type in (message.EventType.new, message.EventType.update):
            with self.subTest(event_type=event_type.value):
                event = message.ObjectEvent(type=event_type, yeti_object=self.url)
                self.assertTrue(as_consumed(event).event.match(acts_on))
        # Still scoped to URLs once the prefix matches.
        event = message.ObjectEvent(
            type=message.EventType.new,
            yeti_object=observable.Hostname(value="example.com"),
        )
        self.assertFalse(as_consumed(event).event.match(acts_on))

    def test_datadog_metrics(self) -> None:
        acts_on = self.acts_on(
            "plugins.events.public.datadog_metrics", "DatadogMetrics"
        )
        events = [
            message.ObjectEvent(type=message.EventType.delete, yeti_object=self.url),
            message.TagEvent(
                type=message.EventType.new,
                tagged_object=self.url,
                tag_object=tag.Tag(name="malware"),
            ),
        ]
        for event in events:
            with self.subTest(event=type(event).__name__):
                self.assertTrue(as_consumed(event).event.match(acts_on))

    def test_dockerhub_image_event(self) -> None:
        acts_on = self.acts_on("plugins.events.public.dockerhub", "DockerHubImageEvent")
        images = [
            container_image.DockerImage(value="library/nginx:latest"),
            container_image.ContainerImage(value="nginx:latest"),
        ]
        for image in images:
            with self.subTest(image=image.type):
                event = message.ObjectEvent(
                    type=message.EventType.new, yeti_object=image
                )
                self.assertTrue(as_consumed(event).event.match(acts_on))


class DatadogMetricsTagsTest(unittest.TestCase):
    """DatadogMetrics formats the same enum fields into its metric tags."""

    def setUp(self) -> None:
        module = import_event_plugin("plugins.events.public.datadog_metrics")
        self.task = module.DatadogMetrics(**module.DatadogMetrics._defaults)
        # Capture what the flusher would send; a non-None flusher stops run()
        # from starting the real one, so nothing reaches the network.
        self.queue = queue.Queue()
        for patcher in (
            mock.patch.object(module, "metrics_queue", self.queue),
            mock.patch.object(module.DatadogMetrics, "_metrics_flusher", mock.Mock()),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def enqueued(self, event):
        self.task.run(as_consumed(event))
        _, metric, tags = self.queue.get_nowait()
        return metric, [t for t in tags if not t.startswith("env:")]

    def test_object_serie_tags(self) -> None:
        cases = [
            (
                observable.Url(value="http://example.com/x"),
                ["type:observable.url", "event:new"],
            ),
            (
                task.AnalyticsTask(name="analytics"),
                ["type:task.analytics", "event:new"],
            ),
        ]
        for yeti_object, expected in cases:
            with self.subTest(expected=expected):
                event = message.ObjectEvent(
                    type=message.EventType.new, yeti_object=yeti_object
                )
                self.assertEqual(self.enqueued(event), ("yeti.object", expected))

    def test_tag_serie_tags(self) -> None:
        event = message.TagEvent(
            type=message.EventType.delete,
            tagged_object=observable.Url(value="http://example.com/x"),
            tag_object=tag.Tag(name="malware"),
        )
        self.assertEqual(
            self.enqueued(event),
            ("yeti.tagged", ["tag:malware", "type:observable.url", "event:delete"]),
        )
