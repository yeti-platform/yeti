import datetime
from enum import Enum

from core.helpers import refang, REGEXES
from typing import Type

from pydantic import BaseModel, Field
from core import database_arango

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

    @classmethod
    def load(cls, object: dict) -> "Task":
        return cls(**object)
