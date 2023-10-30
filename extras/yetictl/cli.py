from core.schemas.user import UserSensitive


def create_user(username, password, admin=False):
    user = UserSensitive.find(username=username)
    if user:
        raise RuntimeError(f"User with username {username} already exists")
    user = UserSensitive(username=username, admin=admin)
    user.set_password(password)
    user.save()
    print(f"User {username} succesfully created! API key: {username}:{user.api_key}")

def reset_password(username, new_password):
    user = UserSensitive.find(username=username)
    if not user:
        raise RuntimeError(f"User with username {username} could not be found")
    user.set_password(new_password)
    user.reset_api_key()
    user.save()
    print(f"Password for {username} succesfully reset. New API key: {user.api_key}")


def main():
    pass
    # pass do things with click?
