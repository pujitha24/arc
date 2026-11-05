#!/usr/bin/env python3
"""Prove OSS cold reads using freshly generated data and an empty metadata DB.

Never reads or copies existing installations, licenses, data or metadata.
"""
import argparse
import subprocess
import time
import urllib.request

from advanced import Advanced
from run import ROOT, Suite


class ColdRead(Suite):
    storage = Advanced.storage
    s3 = Advanced.s3

    def run(self):
        fixture = self.state/'synthetic.parquet'
        subprocess.run(['go', 'run', './scripts/license_docker/cold_fixture', str(fixture)], cwd=ROOT, check=True)
        self.s3_name, self.s3_port = self.run_id+'-cold-store', None
        self.current = 'cold-read'
        path = 'license_test/synthetic_cold/2026/11/02/synthetic_cold_20261102_daily.parquet'
        try:
            self.storage()
            network = self.run_id+'-cold-read'
            self.docker('network', 'create', '--label', self.label, network)
            self.docker('network', 'connect', '--alias', 'cold-store', network, self.s3_name)
            self.s3('/readonly-cold', 'PUT')
            request = urllib.request.Request('http://127.0.0.1:'+self.s3_port+'/readonly-cold/preserved/archive/'+path,
                                             data=fixture.read_bytes(), method='PUT')
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200:
                    raise RuntimeError('synthetic S3 upload failed')
            env = self.base_env('', '', '', 'cold-read')
            env.update(ARC_CLUSTER_ENABLED='false', ARC_AUTH_ENABLED='false', ARC_AUDIT_LOG_ENABLED='false',
                       ARC_GOVERNANCE_ENABLED='false', ARC_TIERED_STORAGE_SCAN_TIMEOUT='5m',
                       ARC_TIERED_STORAGE_COLD_ENABLED='true', ARC_TIERED_STORAGE_COLD_BACKEND='s3',
                       ARC_TIERED_STORAGE_COLD_S3_BUCKET='readonly-cold',
                       ARC_TIERED_STORAGE_COLD_S3_PREFIX='preserved/archive',
                       ARC_TIERED_STORAGE_COLD_S3_REGION='us-east-1',
                       ARC_TIERED_STORAGE_COLD_S3_ENDPOINT='http://cold-store:8333',
                       ARC_TIERED_STORAGE_COLD_S3_ACCESS_KEY='local-test',
                       ARC_TIERED_STORAGE_COLD_S3_SECRET_KEY='local-test',
                       ARC_TIERED_STORAGE_COLD_S3_USE_SSL='false', ARC_TIERED_STORAGE_COLD_S3_PATH_STYLE='true')
            node = self.start_node('cold-read', 'w1', env)
            self.wait(node)
            time.sleep(11)
            result = self.query_count(node, 'synthetic_cold')
            self.record('oss_reads_synthetic_cold_data_with_nondefault_prefix',
                        result[0] == 200 and result[1].get('columns') == ['n'] and self.count(result[1]) == 30,
                        {'query': result, 'prefix': 'preserved/archive', 'license_key_configured': False,
                         'metadata_initially_empty': True})
            self.record('oss_cold_tiering_management_denied', self.api(node, '/api/v1/tiering/migrate', {})[0] == 403)
            self.docker('restart', '-t', '45', node)
            self.refresh_port(node)
            self.wait(node)
            result = self.query_count(node, 'synthetic_cold')
            self.record('oss_cold_reads_after_restart', result[0] == 200 and result[1].get('columns') == ['n'] and self.count(result[1]) == 30, result)
            code, _ = self.s3('/readonly-cold/preserved/archive/'+path, 'GET')
            self.record('synthetic_cold_object_preserved', code == 200)
        finally:
            for install in {info['install'] for info in self.nodes.values()}:
                self.stop_install(install)
            if self.require_owned('container', self.s3_name):
                self.docker('stop', self.s3_name)
            self.write_report()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', required=True, help='new private state directory')
    p.add_argument('--run-id', required=True)
    p.add_argument('--image', default='arc-license-policy:fast')
    suite = ColdRead(p.parse_args())
    suite.run()
    raise SystemExit(any(row['result'] == 'FAIL' for row in suite.results))


if __name__ == '__main__':
    main()
