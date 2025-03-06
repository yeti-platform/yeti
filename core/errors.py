class YetiError(RuntimeError):
    def __init__(self, message: str, meta: dict | None = None):
        self.meta = meta or {}
        super().__init__(message)


class ObjectCreationError(YetiError):
    pass
