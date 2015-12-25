class GenericYetiErrorError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ObservableValidationError(GenericYetiErrorError):
    pass


class TagValidationError(GenericYetiErrorError):
    pass
