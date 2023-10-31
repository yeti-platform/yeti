import click

from core.schemas.user import UserSensitive, User



@click.group()
def cli():
    pass

@cli.command()
def list_users():
    users = User.list()
    for user in users:
        click.echo(f"Username: {user.username} | API key: {user.api_key} | Admin: {user.admin}")


@cli.command()
@click.argument('username')
@click.argument('password')
@click.option('--admin', is_flag=True, default=False)
def create_user(username: str, password: str, admin: bool = False) -> None:
    """Creates a new user in the system."""
    user = UserSensitive.find(username=username)
    if user:
        raise RuntimeError(f"User with username {username} already exists")
    user = UserSensitive(username=username, admin=admin)
    user.set_password(password)
    user.save()
    click.echo(f"User {username} succesfully created! API key: {username}:{user.api_key}")


@cli.command()
@click.argument('username')
def delete_user(username: str) -> None:
    """Deletes a user from the system."""
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} does not exist")
    user.delete()
    click.echo(f"User {username} succesfully deleted")


@cli.command()
@click.argument('username')
@click.argument('new_password')
def reset_password(username: str, new_password: str) -> None:
    """Resets a user's password."""
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} could not be found")
    user.set_password(new_password)
    user.reset_api_key()
    user.save()
    click.echo(f"Password for {username} succesfully reset. New API key: {user.api_key}")

if __name__ == '__main__':
    cli()
