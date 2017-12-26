import pkgutil
import inspect
import importlib
from mongoengine import DoesNotExist

from core.scheduling import ScheduleEntry, OneShotEntry
from core.analytics import InlineAnalytics
from core.constants import PLUGINS_ROOT

PLUGIN_CLASSES = (ScheduleEntry, OneShotEntry, InlineAnalytics)


def get_plugins():
    entries = {}

    for _, name, ispkg in pkgutil.walk_packages([PLUGINS_ROOT],
                                                prefix="plugins."):
        if not ispkg:
            module = importlib.import_module(name)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(
                        obj, PLUGIN_CLASSES) and obj.default_values is not None:
                    try:
                        entry = obj.objects.get(name=obj.default_values['name'])
                    except DoesNotExist:
                        entry = obj(**obj.default_values)
                        entry.save()

    for sched in ScheduleEntry.objects.all():
        entries[sched.name] = sched

    return entries
