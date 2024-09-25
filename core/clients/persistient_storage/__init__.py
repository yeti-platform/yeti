import os
import importlib
import inspect
from typing import Type

from core.clients.persistient_storage.classes.main import PersistientStorageClient, LocalStorageClient

ignored_files = ["main.py"]

def load_client_classes():
    classes: list[Type[PersistientStorageClient]] = []

    class_directory = os.path.join(os.path.dirname(__file__), "classes")
    for filename in os.listdir(class_directory):
        if filename.endswith(".py") and filename not in ignored_files:
            module_name = filename.removesuffix(".py")

            module = importlib.import_module(f"core.clients.persistient_storage.classes.{module_name}")
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, PersistientStorageClient) and obj != PersistientStorageClient:
                    classes.append(obj)

    return classes

def get_client(path: str) -> PersistientStorageClient:
    for client_class in load_client_classes():
        if path.startswith(client_class.PREFIX):
            return client_class(path)
    return LocalStorageClient(path)