from __future__ import unicode_literals

from datetime import timedelta

from mongoengine.base import BaseField


class TimeDeltaField(BaseField):
    """A TimeDeltaField field.
    Looks to the outside world like a datatime.timedelta, but stores
    in the database as an integer (or float) number of seconds.
    """

    def validate(self, value):
        if not isinstance(value, (timedelta, int, float)):
            self.error('cannot parse timedelta "%r"' % value)

    def to_mongo(self, value):
        return self.prepare_query_value(None, value)

    def to_python(self, value):
        if not value:
            return None
        if isinstance(value, timedelta):
            return value
        if isinstance(value, (int, float, str, bytes)):
            return timedelta(seconds=int(value))

    def prepare_query_value(self, op, value):
        if value is None:
            return value
        if isinstance(value, timedelta):
            return self.total_seconds(value)
        if isinstance(value, (int, float, str, bytes)):
            return int(value)

    @staticmethod
    def total_seconds(value):
        """Implements Python 2.7's datetime.timedelta.total_seconds()
        for backwards compatibility with Python 2.5 and 2.6.
        """
        try:
            return value.total_seconds()
        except AttributeError:
            return (
                (value.days * 24 * 3600)
                + (value.seconds)
                + (value.microseconds / 1000000.0)
            )
