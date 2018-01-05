from __future__ import unicode_literals


class GenericYetiError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


# Validation errors


class GenericValidationError(GenericYetiError):
    pass


class ObservableValidationError(GenericValidationError):
    pass


class IndicatorValidationError(GenericValidationError):
    pass


class EntityValidationError(GenericValidationError):
    pass


class TagValidationError(GenericYetiError):
    pass
