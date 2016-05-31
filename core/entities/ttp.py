from mongoengine import *

from core.entities import Entity


class TTP(Entity):

    KILL_CHAIN_STEPS = {"1": "Reconnaissance",
                        "2": "Weaponisation",
                        "3": "Delivery",
                        "4": "Exploitation",
                        "5": "Installation",
                        "6": "C2",
                        "7": "Objectives"}

    killchain = StringField(verbose_name="Kill Chain Stage", choices=KILL_CHAIN_STEPS.items(), required=True)

    DISPLAY_FIELDS = Entity.DISPLAY_FIELDS + [("killchain", "Kill Chain")]

    meta = {
        "ordering": ["killchain"],
    }

    def __init__(self, *args, **kwargs):
        super(TTP, self).__init__(*args, **kwargs)
        self.get_killchain_display = self.get_killchain_display

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['name', 'killchain', 'description']}
        i['id'] = str(self.id)
        i['type'] = 'TTP'
        return i

    def generate_tags(self):
        return [self.killchain.lower(), self.name.lower()]
