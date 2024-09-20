import json
import logging
import sys
import traceback

import click
from core.schemas.task import Task, TaskParams, TaskType
from core.schemas.user import User, UserSensitive
from core.taskmanager import TaskManager
from core.taskscheduler import get_plugins_list


@click.group()
def cli():
    pass


@cli.command()
def list_users():
    users = User.list()
    for user in users:
        click.echo(
            f"Username: {user.username} | API key: {user.api_key} | Admin: {user.admin}"
        )


@cli.command()
@click.argument("username")
@click.argument("password")
@click.option("--admin", is_flag=True, default=False)
@click.option("--api_key")
def create_user(
    username: str, password: str, admin: bool = False, api_key: str | None = None
) -> None:
    """Creates a new user in the system."""
    user = UserSensitive.find(username=username)
    if user:
        raise RuntimeError(f"User with username {username} already exists")
    user = UserSensitive(username=username, admin=admin)
    user.set_password(password)
    if api_key:
        user.reset_api_key(api_key=api_key)
    user.save()
    click.echo(
        f"User {username} succesfully created! API key: {username}:{user.api_key}"
    )


@cli.command()
@click.argument("username")
def toggle_user(username: str):
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} does not exist")
    user.enabled = not user.enabled
    user.save()
    click.echo(
        f"User {username} succesfully {'enabled' if user.enabled else 'disabled'}"
    )


@cli.command()
@click.argument("username")
def toggle_admin(username: str):
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} does not exist")
    user.admin = not user.admin
    user.save()
    click.echo(
        f"User {username} succesfully {'promoted to admin' if user.admin else 'demoted from admin'}"
    )


@cli.command()
@click.argument("username")
def delete_user(username: str) -> None:
    """Deletes a user from the system."""
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} does not exist")
    user.delete()
    click.echo(f"User {username} succesfully deleted")


@cli.command()
@click.argument("username")
@click.argument("new_password")
def reset_password(username: str, new_password: str) -> None:
    """Resets a user's password."""
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} could not be found")
    user.set_password(new_password)
    user.reset_api_key()
    user.save()
    click.echo(
        f"Password for {username} succesfully reset. New API key: {user.api_key}"
    )


@cli.command()
def list_task_types() -> None:
    """Lists all task types."""
    for task_type in TaskType:
        click.echo(f"{task_type}")


@cli.command()
@click.argument("task_type", required=False)
def list_tasks(task_type="") -> None:
    """Lists all tasks of a certain type."""
    # Load all tasks. Take into account new tasks that have not been registered
    get_plugins_list()
    tasks = list()
    for task in Task.list():
        if task_type and task.type != task_type:
            continue
        tasks.append(task)
    for task in sorted(tasks, key=lambda x: x.name):
        click.echo(f"{task.name}")


@cli.command()
@click.argument("task_name")
@click.argument("task_params", required=False)
def run_task(task_name: str, task_params: dict = None) -> None:
    """Runs a task."""
    # Load all tasks. Take into account new tasks that have not been registered
    logging.getLogger().setLevel(logging.INFO)
    get_plugins_list()
    task = TaskManager.load_task(task_name)
    if not task:
        click.echo("Task {task_name} not found.")
    if task_params:
        try:
            task_params = TaskParams(params=json.loads(task_params))
        except json.JSONDecodeError:
            click.echo("Could not parse task_params")
    try:
        if task_params:
            task.run(params=task_params.params)
        else:
            task.run()
    except Exception as error:  # pylint: disable=broad-except
        # We want to catch and report all errors
        click.echo(f"Error running task {task_name}: {error}")
        click.echo(traceback.format_exc())


if __name__ == "__main__":
    cli()
