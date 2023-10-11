import os
from configparser import ConfigParser

from core.constants import YETI_ROOT


class Dictionary(dict):
    """A dictionary that allows to access its elements as attributes."""

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

    def find_env_variable(self, section, key) -> bool | int | str | None:
        """Attempts to find an environment variable corresponding to the setting.

        Environment variables should be defined with the following format:
          YETI_<SECTION>_<KEY>

        Args:
            section: The section of the setting as it appears in the config file.
            key: They key of the setting as it appears in the config file.
        """
        env_var = f"YETI_{section.upper()}_{key.upper()}"
        if env_var in os.environ:
            var = os.environ[env_var]
            if var.lower() in ["true", "false"]:
                return var.lower() == "true"
            if var.isdigit():
                return int(var)
            return var
        return None

    def get(self, section, key=None, default=None):
        """Gets a setting from the config file."""
        if key is None:
            return getattr(self, section)
        if hasattr(self, section) and key in self[section]:
            return self[section][key]
        else:
            env_var = self.find_env_variable(section, key)
            if env_var is not None:
                return env_var
            return default

yeti_config = Config()
