import datetime
from enum import Enum

from core.helpers import refang, REGEXES
from typing import Type

from pydantic import BaseModel, Field
from core import database_arango
from core.schemas.observable import Observable


def now():
    return datetime.datetime.now(datetime.timezone.utc)


class TaskStatus(str, Enum):
    idle = 'idle'
    running = 'running'
    completed = 'completed'
    failed = 'failed'

class TaskType(str, Enum):
    feed = 'feed'
    analytics = 'analytics'
    oneshot = 'oneshot'
    inline = 'inline'
    export = 'export'

class Task(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'tasks'
    _type_filter: str = ''
    _defaults: dict = {}

    id: str | None = None
    name: str
    type: TaskType
    enabled: bool = True
    description: str = ''
    status: TaskStatus = TaskStatus.idle
    status_message: str = ''
    last_run: datetime.datetime | None = None

    # only used for cron tasks
    frequency: datetime.timedelta = datetime.timedelta(days=1)

    def run(self):
        """Runs the task"""
        raise NotImplementedError('run() must be implemented in subclass')

    @classmethod
    def load(cls, object: dict) -> "TaskTypes":
        # If this is called using Task, then return a Task or AnalyticsTask
        if cls == Task and object['type'] in TYPE_MAPPING:
            cls = TYPE_MAPPING[object['type']]
        # Otherwise, use the actual cls.
        return cls(**object)


class AnalyticsTask(Task):

    acts_on: list[str] = []  # By default act on all observables

    def run(self):
        """Filters observables to analyze and then calls each()"""
        targets = Observable.filter(args={'type__in': self.acts_on})[0]
        self.bulk(targets)

    def bulk(self, observables: list[Observable]):
        """Analyzes a set of observables. Can be overriden if needed."""
        for observable in observables:
            assert observable.id is not None
            self.each(observable)
            self.analysis_done(observable.id)

    def analysis_done(self, observable_id: str):
        """Updates the status of the analysis for a given observable"""
        # TODO: Write a function that just updates a single field.
        observable = Observable.get(observable_id)
        assert observable is not None
        observable.last_analysis[self.name] = now()
        observable.save()

    def each(self, observable: Observable) -> Observable:
        """Analyzes a single observable.

        Args:
            observable: The observable to analyze.

        Returns:
            The observable that was processed, to track last analysis."""
        raise NotImplementedError

TYPE_MAPPING = {
    'analytics': AnalyticsTask,
    'feed': Task,
}

TaskTypes =  Task | AnalyticsTask
