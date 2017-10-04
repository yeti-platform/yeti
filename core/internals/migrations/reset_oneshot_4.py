from core.scheduling import OneShotEntry

__description__ = "Reload one shot entries from file system."


def migrate():
    OneShotEntry.drop_collection()
