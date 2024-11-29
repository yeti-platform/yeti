from typing import Callable


class MigrationManager:
    MIGRATIONS: list[Callable] = []

    def __init__(self):
        self.connect_to_db()

    def connect_to_db(self):
        raise NotImplementedError

    def update_db_version(self, version: int):
        raise NotImplementedError

    def migrate_to_latest(self, stop_at: int = None):
        for idx, migration in enumerate(self.MIGRATIONS):
            if stop_at is not None and idx >= stop_at:
                print(f"Stopping at migration {idx}")
            elif idx >= self.db_version and (stop_at is None or idx < stop_at):
                print(f"Running migration {idx} -> {idx + 1}")
                migration()
                self.update_db_version(idx + 1)
            else:
                print(f"Skipping migration {idx}, current version is {self.db_version}")
                continue

    @classmethod
    def register_migration(cls, migration):
        cls.MIGRATIONS.append(migration)
