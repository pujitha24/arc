#!/usr/bin/env python3
"""Crash the primary in each real-key installation and observe licensed failover."""
import argparse
import datetime as dt
import json
from pathlib import Path
import time
from run import Suite, UTC


class Failover(Suite):
    def __init__(self, args):
        super().__init__(args)
        self.installations = json.loads((self.state / 'report.json').read_text())['installations']
        self.results = []
        for file in args.key_files:
            key = Path(file).read_text().strip()
            self.secret(key)
            self.secret(key[:12])

    def write_report(self):
        if not self.installations:
            return
        self.private(self.state / 'failover-report.json', json.dumps(self.redact(dict(
            **self.provenance(), evidence_class='real licenses / crash failover', generated_at=dt.datetime.now(UTC).isoformat(),
            installations=self.installations, results=self.results)), indent=2))

    def run(self):
        s3 = self.run_id+'-cold-store'
        self.docker('start', s3)
        for installation in self.installations:
            install = self.current = installation['id']
            names = [n for n, i in self.nodes.items() if i['install'] == install
                     and not (installation['signed_license']['max_machines'] == 3 and i['role'] == 'r1')]
            victim = None
            try:
                # Cold testing used a dedicated compactor. Restore three writer
                # voters so an unlicensed automatic failover cannot be confused
                # with quorum loss after the primary is killed.
                for name in names:
                    info = self.nodes[name]
                    path = self.state / install / info['role'] / 'node.env'
                    env = dict(line.split('=', 1) for line in path.read_text().splitlines() if line)
                    self.verify_container(name, env, self.args.image)
                    wanted_role = 'reader' if info['role'] == 'r1' else 'writer'
                    if env.get('ARC_CLUSTER_ROLE') != wanted_role:
                        self.docker('stop', '-t', '45', name, check=False)
                        self.docker('rm', name)
                        env['ARC_CLUSTER_ROLE'] = wanted_role
                        self.start_node(install, info['role'], env, cluster_role=wanted_role)
                self.docker('start', *names)
                for name in names:
                    self.refresh_port(name)
                    self.wait(name)
                deadline = time.monotonic()+45
                ready = []
                while time.monotonic() < deadline:
                    ready = [n for n in names if self.api(n, '/ready/write')[0] == 200]
                    if len(ready) == 1:
                        break
                    time.sleep(.5)
                self.record('exactly_one_primary_before_crash', len(ready) == 1, ready)
                if len(ready) != 1:
                    continue
                self.wait(ready[0], '/api/v1/cluster', predicate=lambda b: b.get('raft', {}).get('membership', {}).get('voting_servers') == 3)
                victim = ready[0]
                before = self.query_count(victim)
                self.docker('kill', '--signal', 'KILL', victim)
                peers = [n for n in names if n != victim]
                automatic = 'writer_failover' in installation['signed_license']['features']
                samples = []
                start = time.monotonic()
                while time.monotonic()-start < 65:
                    writers = [n for n in peers if self.api(n, '/ready/write', timeout=3)[0] == 200]
                    samples.append(dict(seconds=round(time.monotonic()-start, 1), ready=writers))
                    if automatic and writers:
                        break
                    time.sleep(2)
                probe = self.api(peers[0], '/api/v1/rbac/organizations', {'name': 'quorum-probe-'+self.case_id})
                cluster = self.api(peers[0], '/api/v1/cluster')
                eligible = [n for n in cluster[1].get('nodes', []) if n.get('role') == 'writer' and n.get('state') == 'healthy' and n.get('id') != self.nodes[victim]['hostname']]
                quorum = probe[0] == 201 and bool(eligible)
                self.record('surviving_peers_commit_raft_write', quorum, {'probe': probe, 'healthy_writer_peers': len(eligible)})
                self.record('automatic_writer_failover_entitlement',
                            quorum and (len(writers) == 1 if automatic else len(writers) == 0),
                            samples, 'one replacement writer' if automatic else 'no automatic replacement')
                if writers:
                    after = self.query_count(writers[0])
                    self.record('replicated_rows_survive_primary_crash', after[0] == 200 and self.count(after[1]) == self.count(before[1]), after)
                self.docker('start', victim)
                self.refresh_port(victim)
                self.wait(victim)
                deadline = time.monotonic()+45
                while time.monotonic() < deadline:
                    ready = [n for n in names if self.api(n, '/ready/write')[0] == 200]
                    if len(ready) == 1:
                        break
                    time.sleep(.5)
                self.record('one_writer_after_original_node_returns', len(ready) == 1, ready)
                after = self.query_count(ready[0] if ready else victim)
                self.record('rows_preserved_after_crash_recovery', after[0] == 200 and self.count(after[1]) == self.count(before[1]), after)
            except Exception as error:
                self.record('failover_exception', False, str(error))
            finally:
                if victim:
                    self.docker('start', victim, check=False)
                self.stop_install(install)
        self.docker('stop', s3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('--image', default='arc-license-tests:dde0bbeb')
    parser.add_argument('--run-id', default='arc-license-live')
    parser.add_argument('key_files', nargs='+')
    suite = Failover(parser.parse_args())
    suite.run()
    return int(any(x['result'] == 'FAIL' for x in suite.results))


if __name__ == '__main__':
    raise SystemExit(main())
