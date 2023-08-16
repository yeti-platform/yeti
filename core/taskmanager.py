import logging
import datetime

from celery import Celery
from core.schemas.task import Task, TaskStatus
from typing import Type
import traceback


app = Celery(
    'tasks',
    broker='redis://redis/',
    imports = (
        # TESTING ONLY
        "plugins.feeds.public.random",
        "plugins.analytics.public.random_analytics",
        "plugins.feeds.public.abusech_malwarebazaar",
    ))


class TaskManager():

    _store = {}  # type: dict[str, Task]

    @classmethod
    def register_task(cls, task_class: Type[Task], task_name: str | None = None):
        """Registers task in cache.

        task_class: The task class to register.
        task_name: The name of the task. Used with Exports, which all share
            the same class.

        Will create DB entry if it does not exist.
        """
        if not task_name:
            task_name = task_class.__name__
        logging.info('Registering task', task_name)
        task = task_class.find(name=task_name)
        if not task:
            logging.info('Task not found in database, creating.')
            task_dict = task_class._defaults.copy()
            task_dict['name'] = task_name
            task = task_class(**task_dict).save()
        cls._store[task_name] = task

    @classmethod
    def get_task(cls, task_name):
        """Retreives task from cache."""
        return cls._store[task_name]

    @classmethod
    def load_task(cls, task_name) -> Task:
        """Loads tasks from the database and refreshes cache."""
        if task_name not in cls._store:
            # ExportTasks are
            logging.error(f'Task {task_name} not found. Was it registered?')
            logging.error('Registered tasks: ', cls._store.keys())
            raise ValueError(f'Task {task_name} not found. Was it registered?')

        task_class = cls._store[task_name].__class__
        task = task_class.find(name=task_name)
        cls._store[task_name] = task
        return task

    @classmethod
    def run_task(cls, task_name):
        logging.info(f"Running task {task_name}")
        task = TaskManager.load_task(task_name)
        if not task.enabled:
            task.status_message = 'Task is disabled.'
            task.status = TaskStatus.failed
            task.save()
            return

        if task.status == TaskStatus.running:
            task.save()
            return

        task.status = TaskStatus.running
        task.save()

        try:
            task.run()
        except Exception as error:  # pylint: disable=broad-except
            # We want to catch and report all errors
            logging.error(traceback.format_exc())
            task.status = TaskStatus.failed
            task.status_message = str(error)
            task.save()
            return

        task.status = TaskStatus.completed
        task.last_run = datetime.datetime.now(datetime.timezone.utc)
        task.status_message = ''
        task.save()

@app.task
def run_task(task_name):
    TaskManager.run_task(task_name)
