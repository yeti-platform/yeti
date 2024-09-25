from abc import ABC, abstractmethod
import pathlib
import os

class PersistientStorageClient(ABC):
    PREFIX: str

    @abstractmethod
    def __init__(self, path: str):
        raise NotImplementedError
    
    @abstractmethod
    def file_path(self, file_name: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_file(self, file_name: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def put_file(self, file_name: str, contents: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete_file(self, file_name: str) -> None:
        raise NotImplementedError

class LocalStorageClient(PersistientStorageClient):
    PREFIX = ""

    def __init__(self, path: str):
        self.path = pathlib.Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

        print(f"Initialized local storage client with path {self.path}")
    
    def file_path(self, file_name: str) -> str:
        file_path = self.path / file_name
        return str(file_path)

    def get_file(self, file_name: str) -> bytes:
        with open(self.file_path(file_name), "rb") as file:
            return file.read()

    def put_file(self, file_name: str, contents: bytes) -> None:
        with open(self.file_path(file_name), "wb") as file:
            file.write(contents)

    def delete_file(self, file_name: str) -> None:
        os.remove(self.file_path(file_name))
