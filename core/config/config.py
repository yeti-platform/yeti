import os
import ConfigParser

from core.constants import YETI_ROOT


class Dictionary(dict):

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Config:

    def __init__(self):
        config = ConfigParser.SafeConfigParser(allow_no_value=True)
        config.read(os.path.join(YETI_ROOT, "yeti.conf"))

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name in config.options(section):
                try:
                    value = config.getint(section, name)
                except ValueError:
                    try:
                        value = config.getboolean(section, name)
                    except ValueError:
                        value = config.get(section, name)

                getattr(self, section)[name] = value

    def __getitem__(self, key):
        return getattr(self, key)

    def set_default_value(self, section, key, value):
        if not hasattr(self, section):
            setattr(self, section, Dictionary())

        if key not in self[section]:
            self[section][key] = value

    def get(self, section, key, default=None):
        if not hasattr(self, section) or key not in self[section]:
            return default
        else:
            return self[section][key]


yeti_config = Config()
yeti_config.set_default_value('mongodb', 'host', '127.0.0.1')
yeti_config.set_default_value('mongodb', 'port', 27017)
yeti_config.set_default_value('mongodb', 'database', 'yeti')
yeti_config.set_default_value('mongodb', 'username', None)
yeti_config.set_default_value('mongodb', 'password', None)
yeti_config.set_default_value('redis', 'host', '127.0.0.1')
yeti_config.set_default_value('redis', 'port', 6379)
yeti_config.set_default_value('redis', 'database', 0)
yeti_config.set_default_value('proxy', 'http', None)
yeti_config.set_default_value('proxy', 'https', None)
yeti_config.set_default_value('logging', 'filename', 'userlogs')
