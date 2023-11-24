import importlib
import inspect
import json
import logging
import pathlib
import pkgutil

from celery import Celery
from celery.utils.log import get_task_logger
from core.config.config import yeti_config
from core.schemas.task import Task, TaskParams
from core.taskmanager import TaskManager

logger = get_task_logger(__name__)

def get_plugins_list():
    plugins_list = set()
    plugins_path = pathlib.Path(yeti_config.get('system', 'plugins_path'))
    if not plugins_path.exists():
        logging.warning(f"Plugins path {str(plugins_path.absolute())} does not exist")
        return plugins_list
    for module_info in pkgutil.walk_packages([str(plugins_path.absolute())], prefix=f"{plugins_path.name}."):
        if not module_info.ispkg:
            try:
                module = importlib.import_module(module_info.name)
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, Task):
                        plugins_list.add(module_info.name)
            except Exception as error:
                logging.warning(f"Cannot import plugin {module_info.name}\n{error}")
    return plugins_list


app = Celery(
    "tasks",
    broker=f"redis://{yeti_config.get('redis', 'host')}/",
    worker_pool_restarts=True,
    imports=get_plugins_list()
)

@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Registers periodic tasks."""
    for task in Task.list():
        if not task.frequency:
            continue
        logger.info("Registering periodic task %s (%s)", task.name, task.frequency)
        sender.add_periodic_task(
            task.frequency,
            run_task.s(task.name, '{}'),
            name=f'Schedule for {task.name}')
    return

@app.task
def run_task(task_name: str, params: str):
    """Runs a task.

    Args:
        task_name: The name of a registered task to run.
        params: A string-encoded JSON representation of a TaskParams object
            (obtained through model_dump_json)
    """
    task_params = TaskParams(**json.loads(params))
    TaskManager.run_task(task_name, task_params)

