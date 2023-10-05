import os
from configparser import ConfigParser

from core.constants import YETI_ROOT


class Dictionary(dict):
    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Config:
    def __init__(self):
        config = ConfigParser(allow_no_value=True)
        config.read(os.path.join(YETI_ROOT, "yeti.conf"), encoding="utf-8")

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
yeti_config.set_default_value("auth", "module", "local")
yeti_config.set_default_value("auth", os.getenv("YETI_AUTH_SECRET_KEY", "SECRET"))
yeti_config.set_default_value("auth", os.getenv("YETI_AUTH_ALGORITHM", "HS256"))
yeti_config.set_default_value("auth", int(os.getenv("YETI_AUTH_ACCESS_TOKEN_EXPIRE_MINUTES", "30")))
yeti_config.set_default_value("auth", os.getenv("YETI_AUTH_ENABLED", "False") == "True")

yeti_config.set_default_value("redis", "host", os.getenv("YETI_REDIS_HOST", "127.0.0.1"))
yeti_config.set_default_value("redis", "port", int(os.getenv("YETI_REDIS_PORT", "6379")))
yeti_config.set_default_value("redis", "database", int(os.getenv("YETI_REDIS_DATABASE", "0")))

yeti_config.set_default_value("arangodb", "host", os.getenv("YETI_ARANGODB_HOST", "127.0.0.1"))
yeti_config.set_default_value("arangodb", "port", int(os.getenv("YETI_ARANGODB_PORT", "8529")))
yeti_config.set_default_value("arangodb", "username", os.getenv("YETI_ARANGODB_USERNAME", "root"))
yeti_config.set_default_value("arangodb", "password", os.getenv("YETI_ARANGODB_PASSWORD", "asd"))
yeti_config.set_default_value("arangodb", "database", os.getenv("YETI_ARANGODB_DATABASE", "yeti"))

yeti_config.set_default_value("proxy", "http", os.getenv("YETI_PROXY_HTTP", None))
yeti_config.set_default_value("proxy", "https", os.getenv("YETI_PROXY_HTTPS", None))
yeti_config.set_default_value("logging", "filename", os.getenv("YETI_LOGFILE", "/var/log/yeti/user_activity.log"))
