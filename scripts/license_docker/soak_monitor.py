#!/usr/bin/env python3
"""Observe natural real-key expiry without controlling Arc or the host clock."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import urllib.error
import urllib.request
import uuid

UTC = dt.timezone.utc
STATE = Path('/state')
CONFIG = None
SECRETS = []
ACKS = {}
LEDGER = STATE/'write-ledger.jsonl'
UPTIMES = {}
LAST_LICENSE = {}
METADATA = {}
LAST_RETENTION_FEED = {}


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, str):
        for secret in SECRETS:
            value = value.replace(secret, '[REDACTED]')
    return value


def append(path, row):
    with path.open('a', encoding='utf-8') as out:
        out.write(json.dumps(clean(row), separators=(',', ':'))+'\n')
        out.flush()
        os.fsync(out.fileno())


def alert(kind, install, **evidence):
    append(STATE/'alerts.jsonl', dict(time=dt.datetime.now(UTC).isoformat(), kind=kind, installation=install, **evidence))


def request(node, install, path, payload=None, token=None, database='license_soak'):
    headers = {'Authorization': 'Bearer '+(token or install['admin_token']), 'X-Arc-Database': database}
    if isinstance(payload, str):
        data = payload.encode()
        headers['Content-Type'] = 'text/plain'
    else:
        data = None if payload is None else json.dumps(payload).encode()
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(node['url']+path, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, TimeoutError) as error:
        return {'http': 0, 'error': str(error)}
    with response:
        body = response.read()
        try:
            body = json.loads(body)
        except ValueError:
            body = body.decode(errors='replace')[:1200]
        return {'http': response.status, 'body': body}


def values(result):
    body = result.get('body', {})
    if result['http'] != 200 or not isinstance(body, dict) or len(body.get('data', [])) != 1:
        return {}
    row = body['data'][0]
    return dict(zip(body.get('columns', []), row)) if isinstance(row, list) else row


def cluster_summary(result):
    body = result.get('body', {})
    if not isinstance(body, dict):
        return result
    out = {k: body.get(k) for k in ('enabled', 'running', 'mode', 'local_role', 'primary_writer_id', 'node_count')}
    raft = body.get('raft', {})
    out['raft'] = {k: raft.get(k) for k in ('enabled', 'state', 'is_leader', 'leader_id')}
    out['nodes'] = [{k: n.get(k) for k in ('id', 'role', 'state', 'writer_state')} for n in body.get('nodes', [])]
    return {'http': result['http'], 'body': out}


def metadata(node):
    path = Path(node['metadata'])/'arc.db'
    try:
        with sqlite3.connect('file:'+str(path)+'?mode=ro', uri=True, timeout=2) as db:
            out = {}
            names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            for name in names:
                if not (name.startswith('rbac_') or name in ('tiering_policies', 'retention_policies', 'continuous_queries', 'governance_policies')):
                    continue
                quoted = '"'+name.replace('"', '""')+'"'
                # Scheduler watermarks and execution timestamps are observed
                # separately; changing them is not a configuration mutation.
                columns = [r[1] for r in db.execute('PRAGMA table_info('+quoted+')')
                           if not r[1].startswith('last_') and r[1] != 'updated_at']
                selected = ','.join('"'+column.replace('"','""')+'"' for column in columns)
                rows = sorted(map(repr, db.execute('SELECT '+selected+' FROM '+quoted).fetchall()))
                out[name] = {'rows': len(rows), 'columns': columns,
                             'sha256': hashlib.sha256(repr(rows).encode()).hexdigest()}
            return out
    except (sqlite3.Error, OSError) as error:
        return {'error': str(error)}


def sample(install, detailed, audit_ids=False):
    name = install['id']
    now = dt.datetime.now(UTC).isoformat()
    observations = {}
    ready = []
    for node in install['nodes']:
        health = request(node, install, '/health')
        read = request(node, install, '/ready')
        write = request(node, install, '/ready/write')
        observations[node['id']] = {'health': health, 'ready': read['http'], 'ready_write': write['http']}
        body = health.get('body', {})
        if isinstance(body, dict):
            uptime = body.get('uptime_sec')
            if isinstance(uptime, (int, float)):
                previous = UPTIMES.get(node['id'])
                if previous is not None and uptime < previous:
                    alert('process_uptime_decreased', name, node=node['id'], previous=previous, current=uptime)
                UPTIMES[node['id']] = uptime
            status = body.get('license', {}).get('status')
            if status is not None:
                if node['id'] in LAST_LICENSE and LAST_LICENSE[node['id']] != status:
                    alert('license_status_changed', name, node=node['id'], before=LAST_LICENSE[node['id']], after=status)
                LAST_LICENSE[node['id']] = status
        if write['http'] == 200 and node['writer']:
            ready.append(node)
        if detailed:
            observations[node['id']]['cluster'] = cluster_summary(request(node, install, '/api/v1/cluster'))
    if len(ready) != 1:
        alert('writable_node_count', name, count=len(ready), nodes=[n['id'] for n in ready])
    # Exactly one destination: this observer does not fan out writes or change ownership.
    selected = ready[0] if ready else next(n for n in install['nodes'] if n['writer'])
    probe = uuid.uuid4().hex
    append(LEDGER, {'time': now, 'installation': name, 'kind': 'intent', 'probe_id': probe})
    write = request(selected, install, '/api/v1/write/line-protocol',
                    f"license_soak_events,installation={name},probe_id={probe} value=1i {time.time_ns()}\n")
    if write['http'] == 204:
        append(LEDGER, {'time': dt.datetime.now(UTC).isoformat(), 'installation': name, 'kind': 'ack', 'probe_id': probe})
        ACKS[name].add(probe)
    else:
        alert('probe_write_not_acknowledged', name, response=write)
    query = None
    result = {}
    for attempt in range(4):
        time.sleep(1)
        query = request(selected, install, '/api/v1/query',
                        {'sql': 'SELECT count(*) AS n, count(DISTINCT probe_id) AS unique_ids FROM license_soak_events'})
        result = values(query)
        if result.get('n', -1) >= len(ACKS[name]):
            break
    if result.get('n', -1) < len(ACKS[name]):
        alert('acknowledged_rows_missing_or_unreadable', name, confirmed_acks=len(ACKS[name]), query=query)
    if result and result.get('n') != result.get('unique_ids'):
        alert('duplicate_probe_rows', name, counts=result)
    row = dict(time=now, installation=name, signed_expires_at=install['expires_at'], nodes=observations,
               selected_writer=selected['id'], probe_write=write, confirmed_ack_count=len(ACKS[name]), query=query)
    if audit_ids:
        present = set()
        audit_error = None
        offset = 0
        while True:
            page = request(selected, install, '/api/v1/query', {'sql':
                'SELECT DISTINCT probe_id FROM license_soak_events ORDER BY probe_id LIMIT 1000 OFFSET '+str(offset)})
            body = page.get('body', {})
            if page['http'] != 200 or not isinstance(body, dict) or body.get('columns') != ['probe_id']:
                audit_error = page
                break
            rows = body.get('data', [])
            present.update(r[0] if isinstance(r, list) else r['probe_id'] for r in rows)
            if len(rows) < 1000:
                break
            offset += 1000
        missing = ACKS[name]-present if audit_error is None else set()
        row['ack_id_audit'] = {'confirmed_ack_ids': len(ACKS[name]), 'observed_unique_ids': len(present),
                               'missing_count': len(missing), 'error': audit_error}
        if missing:
            alert('confirmed_ack_ids_missing', name, count=len(missing), sample=sorted(missing)[:10])
        if audit_error:
            alert('ack_id_audit_inconclusive', name, response=audit_error)
    if detailed:
        row['features'] = {path: request(selected, install, path) for path in
                           ('/api/v1/rbac/organizations', '/api/v1/tiering/status', '/api/v1/queries/active',
                            '/api/v1/governance/policies', '/api/v1/audit/logs?limit=1', '/api/v1/schedulers/')}
        examples = install.get('examples')
        if examples:
            cq_id, retention_id = int(examples['cq_id']), int(examples['retention_id'])
            row['scheduled_examples'] = {
                'cq': request(selected, install, '/api/v1/continuous_queries/'+str(cq_id)),
                'cq_executions': request(selected, install, '/api/v1/continuous_queries/'+str(cq_id)+'/executions?limit=3'),
                'aggregation_output': request(selected, install, '/api/v1/query',
                    {'sql':'SELECT count(*) AS n FROM license_soak_minute'}),
                'retention': request(selected, install, '/api/v1/retention/'+str(retention_id)),
                'retention_executions': request(selected, install, '/api/v1/retention/'+str(retention_id)+'/executions?limit=3'),
            }
            # New expired rows provide work for the scheduler after every stage.
            # All retention data is separate from the acknowledged main dataset.
            if time.monotonic()-LAST_RETENTION_FEED.get(name, -1000) >= 300:
                stamp = time.time_ns()
                feed_id = uuid.uuid4().hex
                feed = request(selected, install, '/api/v1/write/line-protocol',
                    f'ephemeral,age=old,record_id={feed_id} value=1i {stamp-3*24*3600*10**9}\n'
                    f'ephemeral,age=current,record_id={feed_id} value=1i {stamp}\n', database='license_soak_retention')
                row['scheduled_examples']['retention_feed'] = feed
                LAST_RETENTION_FEED[name] = time.monotonic()
            row['scheduled_examples']['retention_data'] = request(selected, install, '/api/v1/query',
                {'sql':"SELECT age, count(*) AS n FROM ephemeral GROUP BY age ORDER BY age"}, database='license_soak_retention')
        if install.get('cold_measurement'):
            cold = request(selected, install, '/api/v1/query',
                           {'sql': 'SELECT count(*) AS n FROM '+install['cold_measurement']}, database='license_test')
            row['existing_cold_data'] = cold
            if values(cold).get('n') != 30:
                alert('existing_cold_data_count_or_access_changed', name, response=cold)
        if install.get('scoped_token'):
            row['scoped_rbac'] = {measurement: request(selected, install, '/api/v1/query',
                {'sql': 'SELECT count(*) AS n FROM '+measurement}, token=install['scoped_token'], database='license_test')
                for measurement in ('events', 'private_events')}
            if row['scoped_rbac']['events']['http'] != 200 or row['scoped_rbac']['private_events']['http'] != 403:
                alert('rbac_access_or_denial_changed', name, responses=row['scoped_rbac'])
        row['config_metadata'] = {n['id']: metadata(n) for n in install['nodes']}
        for node_id, snapshot in row['config_metadata'].items():
            if node_id in METADATA and 'error' not in snapshot and METADATA[node_id] != snapshot:
                alert('configuration_digest_changed', name, node=node_id)
            if 'error' not in snapshot and node_id not in METADATA:
                METADATA[node_id] = snapshot
        baseline_path = STATE/'metadata-baseline.json'
        temporary = STATE/'metadata-baseline.tmp'
        temporary.write_text(json.dumps(METADATA, indent=2))
        temporary.replace(baseline_path)
        row['peer_counts'] = {n['id']: request(n, install, '/api/v1/query',
            {'sql': 'SELECT count(*) AS n, count(DISTINCT probe_id) AS unique_ids FROM license_soak_events'})
            for n in install['nodes']}
    append(STATE/('events-'+dt.datetime.now(UTC).date().isoformat()+'.jsonl'), row)
    return clean(row)


def load_ledger():
    """Recover complete records; quarantine a torn trailing write before append."""
    if not LEDGER.exists():
        return False
    raw = LEDGER.read_bytes()
    lines = raw.splitlines(keepends=True)
    valid_bytes = 0
    recovered = False
    for index, line in enumerate(lines):
        try:
            event = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            if index != len(lines)-1:
                raise RuntimeError('non-trailing ledger corruption; preserve ledger for investigation')
            suffix = raw[valid_bytes:]
            quarantine = STATE/('write-ledger.torn-'+uuid.uuid4().hex+'.bin')
            with quarantine.open('wb') as out:
                out.write(suffix)
                out.flush()
                os.fsync(out.fileno())
            with LEDGER.open('r+b') as out:
                out.truncate(valid_bytes)
                out.flush()
                os.fsync(out.fileno())
            alert('ledger_torn_suffix_recovered', 'all', quarantined_file=quarantine.name,
                  bytes=len(suffix), note='Partial record is unconfirmed; complete acknowledgments retained.')
            recovered = True
            break
        if event.get('kind') == 'ack':
            ACKS[event['installation']].add(event['probe_id'])
        valid_bytes += len(line)
    if lines and not recovered and not raw.endswith(b'\n'):
        with LEDGER.open('ab') as out:
            out.write(b'\n')
            out.flush()
            os.fsync(out.fileno())
    return recovered


def main():
    global CONFIG, SECRETS, ACKS
    CONFIG = json.loads(Path('/run/soak-config.json').read_text())
    SECRETS = [i[k] for i in CONFIG['installations'] for k in ('admin_token', 'scoped_token') if i.get(k)]
    ACKS = {i['id']: set() for i in CONFIG['installations']}
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    baseline = STATE/'metadata-baseline.json'
    if baseline.exists():
        METADATA.update(json.loads(baseline.read_text()))
    previous = STATE/'latest.json'
    if previous.exists():
        for install in json.loads(previous.read_text()).get('installations', []):
            for node_id, observation in install.get('nodes', {}).items():
                health = observation.get('health', {}).get('body', {})
                if isinstance(health, dict) and isinstance(health.get('uptime_sec'), (int, float)):
                    UPTIMES[node_id] = health['uptime_sec']
                    LAST_LICENSE[node_id] = health.get('license', {}).get('status')
    recovered = load_ledger()
    alert('observer_started', 'all', ledger_torn_suffix_recovered=recovered, note='Observer never restarts Arc or changes clocks. Gaps may reflect machine/container outages.')
    last_detail = 0
    last_audit = 0
    while True:
        started = time.monotonic()
        now = dt.datetime.now(UTC)
        near_boundary = any(abs((dt.datetime.fromisoformat(i['expires_at'].replace('Z', '+00:00'))-now).total_seconds()) < 600 for i in CONFIG['installations'])
        detailed = near_boundary or started-last_detail >= 300
        audit_ids = started-last_audit >= (60 if near_boundary else 3600)
        latest = {'sampled_at': now.isoformat(), 'observer_started_at': CONFIG['started_at'], 'installations': []}
        for install in CONFIG['installations']:
            try:
                latest['installations'].append(sample(install, detailed, audit_ids))
            except Exception as error:
                alert('observer_sample_failed', install['id'], error=str(error))
        if detailed:
            last_detail = started
        if audit_ids:
            last_audit = started
        temporary = STATE/'latest.tmp'
        temporary.write_text(json.dumps(clean(latest), indent=2))
        temporary.replace(STATE/'latest.json')
        time.sleep(max(1, (5 if near_boundary else 60)-(time.monotonic()-started)))


if __name__ == '__main__':
    main()
