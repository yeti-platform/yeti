from core.user import User

__description__ = "Migrate file and attached files permissions."


def migrate():
    for u in User.objects.all():
        u.permissions["attachedfiles"] = u.permissions["files"]
        u.permissions["file"] = {"read": True, "write": True}
        u.permissions.pop("files")
        u.save()
