import os
import importlib
import inspect
from typing import Type

from dev.yeti.core.clients.file_storage.classes.interface import FileStorageClient
from dev.yeti.core.clients.file_storage.classes.local_storage import LocalStorageClient

ignored_files = ["interface.py", "local_storage.py"]

def load_client_classes():
    classes: list[Type[FileStorageClient]] = []

    class_directory = os.path.join(os.path.dirname(__file__), "classes")
    for filename in os.listdir(class_directory):
        if filename.endswith(".py") and filename not in ignored_files:
            module_name = filename.removesuffix(".py")

            module = importlib.import_module(f"core.clients.file_storage.classes.{module_name}")
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, FileStorageClient) and obj != FileStorageClient:
                    classes.append(obj)

    return classes

def get_client(path: str) -> FileStorageClient:
    for client_class in load_client_classes():
        if path.startswith(client_class.PREFIX):
            return client_class(path)
    return LocalStorageClient(path)