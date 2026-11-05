#!/usr/bin/env python3
"""Start an uninterrupted natural-expiry observer on the existing installations."""
import argparse
import datetime as dt
import json
import hashlib
import os
from pathlib import Path
import re

from run import Suite, UTC, ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, help='existing live-test state')
    parser.add_argument('--monitor-state', required=True, help='private persistent observer output')
    parser.add_argument('--run-id', default='arc-license-live')
    parser.add_argument('--image', default='arc-license-tests:dde0bbeb')
    parser.add_argument('--replace-observer', action='store_true', help='replace only the observer; never restart Arc')
    args = parser.parse_args()
    suite = Suite(args)
    folder = Path(args.monitor_state).resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    monitor = args.run_id+'-natural-expiry-observer'
    if suite.require_owned('container', monitor):
        if not args.replace_observer:
            raise RuntimeError('observer already exists; inspect its latest.json rather than restarting it')
        suite.docker('stop', monitor)
        suite.docker('rm', monitor)
    installs = json.loads((suite.state/'report.json').read_text())['installations']
    started_at = dt.datetime.now(UTC).isoformat()
    previous_config = folder/'config.private.json'
    if previous_config.exists():
        started_at = json.loads(previous_config.read_text())['started_at']
    config = {'started_at': started_at, 'installations': []}
    networks = []
    mounts = []
    startup = []
    if not args.replace_observer:
        suite.docker('start', args.run_id+'-cold-store')
    for installation in installs:
        install = installation['id']
        network = args.run_id+'-'+install
        if not suite.require_owned('network', network):
            raise RuntimeError('missing installation network')
        networks.append(network)
        if not args.replace_observer:
            suite.docker('network', 'connect', '--alias', 'cold-store', network, args.run_id+'-cold-store', check=False)
        names = [n for n, i in suite.nodes.items() if i['install'] == install
                 and not (installation['signed_license']['max_machines'] == 3 and i['role'] == 'r1')]
        row = {'id': install, 'key_file': installation['key_file'],
               'expires_at': installation['signed_license']['expires_at'],
               'signed_tier': installation['signed_license']['tier'], 'nodes': []}
        for name in names:
            info = suite.nodes[name]
            env = dict(line.split('=', 1) for line in (suite.state/install/info['role']/'node.env').read_text().splitlines() if line)
            suite.verify_container(name, env, args.image)
            destination = '/metadata/'+install+'/'+info['role']
            mounts += ['-v', info['data']+':'+destination+':ro']
            row['admin_token'] = env['ARC_AUTH_BOOTSTRAP_TOKEN']
            row['nodes'].append({'id': info['hostname'], 'url': 'http://'+info['hostname']+':8000',
                                 'writer': env['ARC_CLUSTER_ROLE'] == 'writer', 'metadata': destination})
        if not args.replace_observer:
            suite.docker('start', *names)
        for name in names:
            if not args.replace_observer:
                suite.refresh_port(name)
                suite.wait(name)
            actual = json.loads(suite.docker('inspect', name).stdout)[0]
            startup.append({'container': name, 'started_at': actual['State']['StartedAt'],
                            'image_id': actual['Image'], 'restart_count': actual['RestartCount'],
                            'state': actual['State']['Status'], 'running': actual['State']['Running']})
        rbac = suite.state/install/'rbac.private.json'
        if rbac.exists():
            row['scoped_token'] = json.loads(rbac.read_text())['token']
        # Most recent published cold fixture for this installation.
        for report_name in ['advanced-report', 'advanced-targeted-recheck', 'advanced-license1-final-recheck']:
            report = suite.state/(report_name+'.json')
            if not report.exists():
                continue
            for check in json.loads(report.read_text())['results']:
                if check.get('installation') == install and check.get('name') == 'daily_compacted_file_exists' and check.get('result') == 'PASS':
                    for path in check['observed']:
                        match = re.search(r'/license_test/(cold_events_[a-z0-9]+)/', path)
                        if match:
                            row['cold_measurement'] = match.group(1)
        examples_path = suite.state/'feature-examples.json'
        if examples_path.exists():
            row['examples'] = next((item for item in json.loads(examples_path.read_text()) if item['id']==install), None)
        config['installations'].append(row)
    suite.private(folder/'config.private.json', json.dumps(config, indent=2))
    source = (ROOT/'scripts/license_docker/soak_monitor.py').read_text()
    suite.private(folder/'observer.py', source)
    suite.private(folder/'startup.json', json.dumps({'started_at': config['started_at'], 'nodes': startup,
        'harness': suite.provenance(), 'observer': monitor,
        'observer_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'observer_created_at': dt.datetime.now(UTC).isoformat(),
        'note': 'Arc remains running. Observer has no Docker socket and never changes clocks or restarts Arc.'}, indent=2))
    suite.docker('create', '--name', monitor, '--label', suite.label, '--network', networks[0],
        '--restart', 'unless-stopped', '--memory', '192m', '--cpus', '.25', '--pids-limit', '64',
        '--user', str(os.getuid())+':'+str(os.getgid()), '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2',
        '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'PYTHONUNBUFFERED=1',
        '-v', str(folder/'config.private.json')+':/run/soak-config.json:ro',
        '-v', str(folder/'observer.py')+':/observer.py:ro',
        '-v', str(folder)+':/state', *mounts, 'python:3.13-slim-bookworm', 'python3', '/observer.py')
    for network in networks[1:]:
        suite.docker('network', 'connect', network, monitor)
    suite.docker('start', monitor)
    print(json.dumps({'observer': monitor, 'installations': len(installs), 'arc_nodes': len(startup),
                      'state': str(folder), 'clock_changes': False, 'automatic_arc_restarts': False}))


if __name__ == '__main__':
    main()
