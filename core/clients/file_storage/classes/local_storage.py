import logging
import os
import pathlib

from core.clients.file_storage.classes.interface import FileStorageClient


class LocalStorageClient(FileStorageClient):
    PREFIX = ""

    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

        logging.info(f"Initialized local storage client with path {self.path}")

    def _file_path(self, file_name: str) -> pathlib.Path:
        return self.path.joinpath(file_name)
    
    def file_path(self, file_name: str) -> str:
        return str(self._file_path(file_name))

    def get_file(self, file_name: str) -> bytes:
        return self._file_path(file_name).read_bytes()        

    def put_file(self, file_name: str, contents: bytes) -> None:
        self._file_path(file_name).write_bytes(contents)

    def delete_file(self, file_name: str) -> None:
        os.remove(self.file_path(file_name))