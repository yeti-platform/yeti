class YetiError(RuntimeError):
    def __init__(self, message: str, meta: dict):
        self.meta = meta
        super().__init__(message)


class ObjectCreationError(YetiError):
    pass
