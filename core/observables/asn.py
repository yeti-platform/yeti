from core.observables import Observable
from mongoengine import IntField


class AutonomousSystem(Observable):

    """Autonomous System observable"""

    as_num = IntField(verbose_name="Autonomous System number")

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [
        ("as_num", "Autonomous System number"),
    ]

    def info(self):
        info = super(AutonomousSystem, self).info()
        info["as_num"] = (self.as_num,)
        return info

    @staticmethod
    def check_type(txt):
        return True
