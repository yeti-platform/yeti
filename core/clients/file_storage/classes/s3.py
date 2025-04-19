import logging
import os

from core.clients.file_storage.classes.interface import FileStorageClient

try:
    import boto3
except ImportError:
    boto3 = None
    logging.warning(
        "boto3 is not imported, if you wish to use s3 file storage please install with `uv sync --group s3`"
    )


class S3Client(FileStorageClient):
    PREFIX = "s3://"

    def __init__(self, path: str):
        if boto3 is None:
            logging.warning(
                "Attempting to use `S3Client` without `boto3` installed; install with `uv sync --group s3`"
            )
            raise ImportError("boto3 is not installed")

        bucket, *prefix = path.removeprefix(self.PREFIX).split("/")

        self.bucket = bucket
        self.prefix = "/".join(prefix)

        self.s3 = boto3.client("s3")

        logging.info(
            f'Initialized S3 client with bucket "{self.bucket}" and prefix "{self.prefix}"'
        )

    def file_path(self, file_name: str) -> str:
        return os.path.join(self.prefix, file_name)

    def get_file(self, file_name: str) -> bytes:
        response = self.s3.get_object(Bucket=self.bucket, Key=self.file_path(file_name))
        return response["Body"].read()

    def put_file(self, file_name: str, contents: bytes) -> None:
        self.s3.put_object(
            Bucket=self.bucket, Key=self.file_path(file_name), Body=contents
        )

    def delete_file(self, file_name: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self.file_path(file_name))
