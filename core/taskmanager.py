import datetime
import json
import logging
import traceback
from typing import Type

from celery import Celery
from celery.utils.log import get_task_logger
from core.config.config import yeti_config
from core.schemas.task import ExportTask, Task, TaskParams, TaskStatus

logger = get_task_logger(__name__)


app = Celery(
    "tasks",
    broker=f"redis://{yeti_config.get('redis', 'host')}/",
    worker_pool_restarts=True,
    imports=(
        # TESTING ONLY
        "plugins.analytics.public.malshare",
        "plugins.analytics.public.passive_total",
        "plugins.analytics.public.random_analytics",
        "plugins.analytics.public.shodan_api",
        "plugins.analytics.public.virustotal_api",
        "plugins.analytics.public.dockerhub",
        # REAL TASKS
        "plugins.feeds.public.attack",
        "plugins.feeds.public.abusech_malwarebazaar",
        "plugins.feeds.public.abuseipdb",
        "plugins.feeds.public.alienvault_ip_reputation",
        "plugins.feeds.public.azorult-tracker",
        "plugins.feeds.public.blocklistde_all",
        "plugins.feeds.public.blocklistde_apache",
        "plugins.feeds.public.blocklistde_bots",
        "plugins.feeds.public.blocklistde_bruteforcelogin",
        "plugins.feeds.public.blocklistde_ftp",
        "plugins.feeds.public.blocklistde_imap",
        "plugins.feeds.public.blocklistde_ircbot",
        "plugins.feeds.public.blocklistde_mail",
        "plugins.feeds.public.blocklistde_sip",
        "plugins.feeds.public.blocklistde_ssh",
        "plugins.feeds.public.blocklistde_strongips",
        "plugins.feeds.public.botvrij_domain",
        "plugins.feeds.public.botvrij_filename",
        "plugins.feeds.public.botvrij_hostname",
        "plugins.feeds.public.botvrij_ipdst",
        "plugins.feeds.public.botvrij_md5",
        "plugins.feeds.public.botvrij_sha1",
        "plugins.feeds.public.botvrij_sha256",
        "plugins.feeds.public.botvrij_url",
        "plugins.feeds.public.cruzit",
        "plugins.feeds.public.cisa_kev",
        "plugins.feeds.public.dataplane_dnsrd",
        "plugins.feeds.public.dataplane_dnsrdany",
        "plugins.feeds.public.dataplane_dnsversion",
        "plugins.feeds.public.dataplane_proto41",
        "plugins.feeds.public.dataplane_sipinvite",
        "plugins.feeds.public.dataplane_sipregistr",
        "plugins.feeds.public.dataplane_smtpdata",
        "plugins.feeds.public.dataplane_smtpgreet",
        "plugins.feeds.public.dataplane_sshclient",
        "plugins.feeds.public.dataplane_sshpwauth",
        "plugins.feeds.public.dataplane_telnetlogin",
        "plugins.feeds.public.dataplane_vnc",
        "plugins.feeds.public.feodo_tracker_ip_blocklist",
        "plugins.feeds.public.futex_re",
        "plugins.feeds.public.hybrid_analysis",
        "plugins.feeds.public.lolbas",
        "plugins.feeds.public.misp",
        "plugins.feeds.public.openphish",
        "plugins.feeds.public.otx_alienvault",
        "plugins.feeds.public.phishing_database",
        "plugins.feeds.public.phishtank",
        "plugins.feeds.public.rulezskbruteforceblocker",
        "plugins.feeds.public.sslblacklist_fingerprints",
        "plugins.feeds.public.sslblacklist_ip",
        "plugins.feeds.public.threatfox",
        "plugins.feeds.public.threatview_c2",
        "plugins.feeds.public.timesketch",
        "plugins.feeds.public.tor_exit_nodes",
        "plugins.feeds.public.urlhaus",
        "plugins.feeds.public.viriback_tracker",
        "plugins.feeds.public.vxvault_url",
    ),
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

class TaskManager:

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
        logging.info(f"Registering task: {task_name}")
        task = task_class.find(name=task_name)
        if not task:
            logging.info(f"Task {task_name} not found in database, creating.")
            task_dict = task_class._defaults.copy()
            task_dict["name"] = task_name
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
            # Only ExportTasks are registered dynamically
            logging.info(f'Registering ExportTask {task_name}')
            cls.register_task(ExportTask, task_name=task_name)

        if task_name not in cls._store:
            logging.error(f"Task {task_name} not found. Was it registered?")
            logging.error(f"Registered tasks: {cls._store.keys()}")
            raise ValueError(f"Task {task_name} not found. Was it registered?")

        task_class = cls._store[task_name].__class__
        task = task_class.find(name=task_name)
        assert task is not None
        cls._store[task_name] = task
        return task

    @classmethod
    def run_task(cls, task_name: str, task_params: TaskParams):
        task = TaskManager.load_task(task_name)
        logging.info("Running task %s (%s)", task.name, task.type)

        if not task.enabled:
            task.status_message = "Task is disabled."
            task.status = TaskStatus.failed
            task.save()
            return

        if task.status == TaskStatus.running:
            task.save()
            return

        task.status = TaskStatus.running
        task.save()

        try:
            if task_params.params:
                task.run(params=task_params.params)
            else:
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
        task.status_message = ""
        task.save()


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
