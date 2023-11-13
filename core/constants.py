from os import path

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
STORAGE_ROOT = path.join(YETI_ROOT, "storage")
PLUGINS_ROOT = path.join(YETI_ROOT, "plugins")
