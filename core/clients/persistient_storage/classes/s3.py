import os

from core.clients.persistient_storage.classes.main import PersistientStorageClient

class S3Client(PersistientStorageClient):
    PREFIX = "s3://"

    def __init__(self, path: str):
        bucket, *prefix = path.removeprefix(self.PREFIX).split("/")

        self.bucket = bucket
        self.prefix = "/".join(prefix)

        import boto3
        self.s3 = boto3.client("s3")

        print(f"Initialized S3 client with bucket \"{self.bucket}\" and prefix \"{self.prefix}\"")

    def file_path(self, file_name: str) -> str:
        return os.path.join(self.prefix, file_name)
    
    def get_file(self, file_name: str) -> str:
        response = self.s3.get_object(Bucket=self.bucket, Key=self.file_path(file_name))
        return response["Body"].read()

    def put_file(self, file_name: str, contents: str) -> None:
        self.s3.put_object(Bucket=self.bucket, Key=self.file_path(file_name), Body=contents)

    def delete_file(self, file_name: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self.file_path(file_name))
