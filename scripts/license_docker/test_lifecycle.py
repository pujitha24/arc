"""Lifecycle fixture contracts; no Docker or network operations."""
from types import SimpleNamespace
import unittest
from urllib.parse import urlparse

from lifecycle_runtime import Lifecycle


class IcebergFixtureTest(unittest.TestCase):
    def env(self, installation):
        suite=Lifecycle.__new__(Lifecycle)
        suite.args=SimpleNamespace(iceberg=True,shared_unlimited=True)
        return suite.base_env('LOCAL-FIXTURE-UNIT','admin','shared',installation)

    def test_explicit_local_warehouse_is_uri(self):
        warehouse=urlparse(self.env('license2')['ARC_ICEBERG_WAREHOUSE'])
        self.assertEqual(warehouse.scheme,'file')
        self.assertEqual(warehouse.path,'/app/data/storage/custom-export')

    def test_shared_warehouse_preserves_object_store_scheme(self):
        env=self.env('license0')
        self.assertEqual(env['ARC_STORAGE_BACKEND'],'s3')
        self.assertEqual(env['ARC_ICEBERG_WAREHOUSE'],'s3://license0-hot/exports')

    def test_default_local_case_keeps_default_catalog_and_warehouse(self):
        env=self.env('license1')
        self.assertNotIn('ARC_ICEBERG_WAREHOUSE',env)
        self.assertNotIn('ARC_ICEBERG_CATALOG_DB_PATH',env)


if __name__=='__main__':
    unittest.main()
