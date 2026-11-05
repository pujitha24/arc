#!/usr/bin/env python3
"""Exercise signed authority time and paid/trial boundaries in disposable clusters.

No host clock changes, real keys or production trust roots are involved.
Topology requirements intentionally fail until the durable handoff is implemented.
"""
import argparse
import datetime as dt
import hashlib
import json
import secrets
import time

from run_fixture import Fixtures
from run import UTC


class PolicyFixtures(Fixtures):
    def oss(self):
        for compaction in (False, True):
            install = 'oss-'+str(compaction).lower()
            self.current = install
            self.docker('network', 'create', '--label', self.label, self.run_id+'-'+install)
            env = self.base_env('', '', '', install)
            env.update(ARC_CLUSTER_ENABLED='false', ARC_AUTH_ENABLED='false',
                       ARC_COMPACTION_ENABLED=str(compaction).lower(), ARC_AUDIT_LOG_ENABLED='false',
                       ARC_GOVERNANCE_ENABLED='false', ARC_TIERED_STORAGE_SCAN_TIMEOUT='5m')
            node = self.start_node(install, 'w1', env)
            self.wait(node)
            time.sleep(11)
            health = self.api(node, '/health')
            query = self.api(node, '/api/v1/query', {'sql': 'SELECT 7 AS smoke'})
            logs = self.docker('logs', node).stdout
            self.record('oss_auth_disabled_tiering_startup', health[0] == 200 and query[0] == 200 and
                        'Tiering manager created' in logs, {'compaction': compaction, 'health': health, 'query': query})
            self.stop_install(install)

    def prepare_policy(self, install, kind, server_time, term, image):
        self.current = install
        self.docker('network', 'create', '--label', self.label, self.run_id+'-'+install)
        self.docker('network', 'connect', '--alias', 'enterprise.basekick.net', self.run_id+'-'+install, self.server_name)
        self.control(mode='valid', activation_mode='valid', license_kind=kind,
                     server_time=server_time, term_ends_at=term, expires_at=term,
                     tier='enterprise', max_machines=10, success_limit=0, reset_events=True)
        admin, shared = self.secret(secrets.token_hex(32)), self.secret(secrets.token_hex(32))
        env = self.base_env('LOCAL-FIXTURE-'+install.upper(), admin, shared, install)
        env['SSL_CERT_FILE'] = '/run/fixture-ca.crt'
        env['ARC_CLUSTER_SEEDS'] = ','.join('arc-license-'+install+'-w'+str(i)+':9100' for i in (1, 2, 3))
        nodes = []
        for role in ('w1', 'w2', 'w3', 'r1'):
            node = self.start_node(install, role, env, image=image,
                                   extra=('-v', str(self.material/'tls.crt')+':/run/fixture-ca.crt:ro'))
            self.wait(node)
            nodes.append(node)
        leader = nodes[0]
        self.wait(leader, '/api/v1/cluster', predicate=lambda b: b.get('node_count') == 4)
        self.wait(leader, '/ready/write')
        stamp = time.time_ns()
        code, body = self.api(leader, '/api/v1/write/line-protocol', ''.join(
            f'events,record_id=p{i} value={i}i {stamp+i}\n' for i in range(20)))
        self.record('baseline_write_ack', code == 204, (code, body))
        self.api(leader, '/api/v1/write/line-protocol', f'private_events value=1i {stamp}\n')
        def visible():
            code, result = self.query_count(leader)
            return code == 200 and result.get('columns') == ['n'] and self.count(result) == 20
        self.record('baseline_read', self.until(visible, timeout=30), self.query_count(leader))
        return leader, nodes

    def health(self, node):
        return self.api(node, '/health')[1].get('license', {})

    def phase(self, nodes, expected):
        ok = self.until(lambda: all(self.health(n).get('desired_policy', {}).get('phase') == expected for n in nodes), timeout=20)
        self.record('signed_time_phase_'+expected, ok, [self.health(n) for n in nodes])
        return ok

    def cache_digests(self, nodes):
        return {n: hashlib.sha256((self.state/self.nodes[n]['install']/self.nodes[n]['role']/'data/license_cache.json').read_bytes()).hexdigest()
                for n in nodes}

    def request_count(self):
        return len(self.authority('/stats')['events'])

    def paid(self):
        leader, nodes = self.prepare_policy('paid-policy', 'paid', '2026-01-08T12:00:00Z', '2026-01-01T12:00:00Z', self.args.image)
        self.phase(nodes, 'grace_full')
        self.record('authority_date_differs_from_host', all(self.health(n).get('evaluated_at', '').startswith('2026-01-08') and
                    self.health(n).get('clock_source') == 'license_server' for n in nodes), [self.health(n) for n in nodes])
        self.rbac(leader)
        # A running process keeps its monotonic anchor through bad refreshes.
        digests = self.cache_digests(nodes)
        for mode in ('bad_time_signature', 'omit_time', 'replay_time'):
            start = self.request_count()
            self.control(mode=mode)
            attempted = self.until(lambda: self.request_count() >= start+2*len(nodes), timeout=20)
            self.record('running_rejects_'+mode+'_without_losing_valid_entitlement', attempted and self.cache_digests(nodes) == digests
                        and all(self.api(n, '/api/v1/queries/active')[0] == 200 for n in nodes))
        self.control(mode='valid')
        self.control(server_time='2025-12-01T00:00:00Z')
        start = self.request_count()
        self.until(lambda: self.request_count() >= start+2*len(nodes), timeout=20)
        self.record('backward_authority_refresh_does_not_undo_phase', all(self.health(n).get('desired_policy', {}).get('phase') == 'grace_full' for n in nodes))
        self.control(server_time='2026-01-08T12:01:00Z')
        self.phase(nodes, 'grace_full')
        # Restart only this synthetic reader. The real-key soak is untouched.
        reader = nodes[-1]
        self.control(mode='503', activation_mode='503')
        self.docker('stop', '-t', '45', reader)
        before = self.cache_digests([reader])
        self.docker('start', reader)
        self.refresh_port(reader)
        sampled = []
        deadline = time.monotonic()+12
        while time.monotonic() < deadline:
            sampled.append(self.api(reader, '/health', timeout=1)[0])
            time.sleep(.5)
        state = json.loads(self.docker('inspect', reader).stdout)[0]['State']
        self.record('restart_outage_waits_with_cache_preserved', all(code != 200 for code in sampled) and state['Running'] and
                    self.cache_digests([reader]) == before, {'http_samples': sampled, 'running': state['Running']})
        self.control(mode='valid', activation_mode='valid')
        self.wait(reader, timeout=60)
        self.record('restart_recovers_only_after_fresh_authority', self.health(reader).get('clock_source') == 'license_server')
        self.control(server_time='2026-01-09T00:00:01Z')
        self.phase(nodes, 'reduced_roles')
        cluster = self.api(leader, '/api/v1/cluster')[1]
        self.record('required_day8_role_contraction', sum(n.get('role') == 'writer' and n.get('state') == 'healthy' for n in cluster.get('nodes', [])) <= 1,
                    cluster, note='Pending topology-controller requirement; a reported phase alone is insufficient.')
        self.control(server_time='2026-01-10T00:00:01Z')
        self.phase(nodes, 'rbac_read_only')
        read = self.api(leader, '/api/v1/rbac/organizations')
        write = self.api(leader, '/api/v1/rbac/organizations', {'name': 'must-be-rejected'})
        self.record('day9_rbac_management_read_only', read[0] == 200 and write[0] == 403, {'read': read[0], 'write': write})
        saved = json.loads((self.state/self.current/'rbac.private.json').read_text())
        membership = self.api(leader, f"/api/v1/auth/tokens/{saved['token_id']}/teams", {'team_id': saved['team']})
        self.record('day9_token_membership_grants_refused', membership[0] == 403, membership)
        token = self.secret(saved['token'])
        allowed = self.api(leader, '/api/v1/query', {'sql': 'SELECT count(*) AS n FROM events'}, token=token)
        denied = self.api(leader, '/api/v1/query', {'sql': 'SELECT count(*) AS n FROM private_events'}, token=token)
        self.record('day9_data_authorization_preserved', allowed[0] == 200 and denied[0] == 403, {'allowed': allowed, 'denied': denied})
        self.control(server_time='2026-01-11T00:00:01Z')
        self.phase(nodes, 'tiering_read_only')
        migrate = self.api(leader, '/api/v1/tiering/migrate', {})
        self.record('day10_new_tiering_migration_refused', migrate[0] == 403, migrate)
        self.control(server_time='2026-01-15T23:59:00Z')
        self.phase(nodes, 'tiering_read_only')
        self.record('day14_other_entitlements_still_work', self.api(leader, '/api/v1/queries/active')[0] == 200)
        self.control(server_time='2026-01-16T00:00:01Z')
        self.phase(nodes, 'oss_required')
        self.record('day15_enterprise_gate_closed', self.api(leader, '/api/v1/queries/active')[0] == 403)
        self.record('day15_existing_data_accessible', self.count(self.query_count(leader)[1]) == 20)
        cluster = self.api(leader, '/api/v1/cluster')[1]
        self.record('required_day15_raft_stopped', not cluster.get('raft', {}).get('enabled', True), cluster,
                    note='Pending durable single-owner OSS handoff; this must not be claimed complete.')
        self.stop_install(self.current)

    def trial(self):
        # Independent synthetic key and fresh processes: paid clock advancement
        # cannot alter this trial's time or the continuously running real trial.
        leader, nodes = self.prepare_policy('trial-policy', 'trial', '2026-01-01T11:59:30Z', '2026-01-01T12:00:30Z', self.args.slow_image)
        self.phase(nodes, 'active')
        start = self.request_count()
        self.record('trial_exact_expiry_without_grace', self.until(lambda: all(self.health(n).get('status') == 'expired' for n in nodes), timeout=75),
                    [self.health(n) for n in nodes])
        self.record('trial_expires_without_further_authority_request', start == self.request_count())
        self.record('trial_enterprise_gate_closed', self.api(leader, '/api/v1/queries/active')[0] == 403)
        self.record('trial_existing_data_accessible', self.count(self.query_count(leader)[1]) == 20)
        self.stop_install(self.current)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', required=True)
    p.add_argument('--material', required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--image', default='arc-license-policy:fast')
    p.add_argument('--slow-image', default='arc-license-policy:slow')
    p.add_argument('--authority-image', default='arc-license-policy-authority:local')
    p.add_argument('--case', choices=('all', 'oss', 'paid', 'trial'), default='all')
    args = p.parse_args()
    suite = PolicyFixtures(args)
    try:
        if args.case in ('all', 'oss'):
            suite.oss()
        if args.case != 'oss':
            suite.setup_authority()
        if args.case in ('all', 'paid'):
            suite.paid()
        if args.case in ('all', 'trial'):
            suite.trial()
    finally:
        for install in {info['install'] for info in suite.nodes.values()}:
            suite.stop_install(install)
        if suite.require_owned('container', suite.server_name):
            suite.docker('stop', suite.server_name)
        suite.write_report()
    raise SystemExit(any(row['result'] == 'FAIL' for row in suite.results))


if __name__ == '__main__':
    main()
