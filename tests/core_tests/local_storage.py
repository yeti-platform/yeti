import pathlib
import tempfile
import unittest

from core.clients.file_storage.classes.local_storage import LocalStorageClient


class LocalStorageClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmpdir_path = str(pathlib.Path(self.tmpdir.name).resolve())
        self.client = LocalStorageClient(self.tmpdir.name)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_file_path_rejects_traversal(self):
        """Tests that a path escaping the storage directory is rejected
        (GHSA-4q3w-w2g5-8wqq)."""
        with self.assertRaises(ValueError):
            self.client.file_path("../../../../../../etc/passwd")

    def test_file_path_allows_normal_names(self):
        path = self.client.file_path("randomexport")
        self.assertTrue(path.startswith(self.tmpdir_path))
