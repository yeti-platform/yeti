import pkgutil
import inspect
import importlib

from core.scheduling import ScheduleEntry, OneShotEntry
from core.analytics import InlineAnalytics
from core.constants import PLUGINS_ROOT

PLUGIN_CLASSES = (ScheduleEntry, OneShotEntry, InlineAnalytics)


def get_plugin_classes():
    classes = []

    for _, name, ispkg in pkgutil.walk_packages([PLUGINS_ROOT],
                                                prefix="plugins."):
        if not ispkg:
            module = importlib.import_module(name)
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(
                        obj, PLUGIN_CLASSES) and obj.default_values is not None:
                    classes.append(obj)

    return classes


def get_plugins():
    entries = {}

    for obj in get_plugin_classes():
        entry = obj.get_or_create(name=obj.default_values['name'])
        if entry.new:
            entry.modify(**obj.default_values)

    for sched in ScheduleEntry.objects.all():
        entries[sched.name] = sched

    return entries
