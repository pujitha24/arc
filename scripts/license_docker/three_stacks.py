#!/usr/bin/env python3
"""Three retained stacks, paid/trial test authorities, expected/actual evidence.

Only synthetic keys reach test authorities. Existing real-server containers are
watched read-only. Production source and existing stacks are never mutated.
"""
import argparse
import base64
import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

from run import ROOT, Suite, UTC


def authority_now(stats):
    if stats.get('effective_server_time'):
        return dt.datetime.fromisoformat(stats['effective_server_time'].replace('Z','+00:00'))
    # Existing retained fixture servers expose their monotonic origin. These
    # containers share this Linux host's monotonic clock (no time namespace).
    # The original-container identity guard prevents resume across a reboot.
    state=stats['state'];elapsed=time.monotonic()-state['time_origin']
    if elapsed<0:raise RuntimeError('authority monotonic origin is not from this boot')
    return dt.datetime.fromisoformat(state['server_time'].replace('Z','+00:00'))+dt.timedelta(seconds=elapsed)


class Matrix(Suite):
    def __init__(self, args):
        super().__init__(args)
        if self.nodes and not args.resume:
            raise RuntimeError('use a new state directory and run ID; never silently reuse stacks')
        self.material = Path(args.material).resolve()/'private'
        self.ssl = ssl.create_default_context(cafile=str(self.material/'tls.crt'))
        self.authorities = {}
        self.profiles = []
        self.expected_ids = collections.defaultdict(set)
        self.baselines = {}
        self.phase_name = 'setup'
        self.original = self.original_snapshot()
        startup = json.loads((Path(args.live_state).parent/'natural-expiry/startup.json').read_text())
        required = {row['container'] for row in startup['nodes']} | {'arc-license-live-cold-store','arc-license-live-natural-expiry-observer'}
        if len(required) != 13 or not required.issubset(self.original):
            raise RuntimeError('expected the eleven original Arc nodes, S3 and observer')
        # Preserve stopped historical capacity probes too, without starting or
        # treating them as one of the eleven continuously running nodes.
        if not all(self.original[name]['running'] for name in required):
            raise RuntimeError('an original stack is already unavailable; inspect before testing')
        prior=self.state/'original-before.json'
        if args.resume and json.loads(prior.read_text()) != self.original:
            raise RuntimeError('original stacks changed since the first run')
        if not args.resume:self.private(prior, json.dumps(self.original, indent=2))
        self.watch_stop, self.watch_failures = threading.Event(), []
        self.watch_samples = 0

    def record(self, name, passed=None, observed=None, expected=None, note=''):
        super().record(self.phase_name+':'+name, passed, observed, expected, note)

    def original_snapshot(self):
        names = subprocess.check_output(['docker', 'ps', '-a', '--filter', 'label=arc-license-tests=arc-license-live', '--format', '{{.Names}}'], text=True).splitlines()
        if not names:
            return {}
        rows = json.loads(subprocess.check_output(['docker', 'inspect', *names], text=True))
        return {r['Name'].lstrip('/'): {'id': r['Id'], 'image': r['Image'], 'started_at': r['State']['StartedAt'],
                'restart_count': r['RestartCount'], 'running': r['State']['Running']} for r in rows}

    def watch_originals(self):
        while not self.watch_stop.is_set():
            try:
                current = self.original_snapshot()
                self.watch_samples += 1
                if current != self.original:
                    self.watch_failures.append({'time': dt.datetime.now(UTC).isoformat(), 'actual': current})
            except Exception as error:
                self.watch_failures.append({'time': dt.datetime.now(UTC).isoformat(), 'error': str(error)})
            self.watch_stop.wait(2)

    def profiles_from_verified_cache(self):
        live = Path(self.args.live_state)
        nodes = json.loads((live/'nodes.private.json').read_text())
        public = re.search(r'const enterprisePublicKeyPEM = `([^`]+)`', (ROOT/'internal/license/pubkey.go').read_text()).group(1)
        for index in range(3):
            install = 'license'+str(index)
            info = next(row for row in nodes.values() if row['install'] == install and row['role'] == 'w1')
            pair = json.loads((Path(info['data'])/'license_cache.json').read_text())
            raw = base64.b64decode(pair['license_file'])
            with tempfile.TemporaryDirectory(dir=self.state) as folder:
                folder = Path(folder)
                self.private(folder/'public.pem', public)
                (folder/'signature').write_bytes(base64.b64decode(pair['license_signature']))
                verified = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(folder/'public.pem'), '-signature', str(folder/'signature')], input=raw, capture_output=True)
                if verified.returncode:
                    raise RuntimeError('production signature did not verify for '+install)
            payload = json.loads(raw)
            selected = {k: payload[k] for k in ('tier', 'features', 'max_cores', 'max_machines')}
            selected.update(id=install, profile_id=install, key_file='.trial_key'+('' if index == 0 else str(index)),
                            license_kind='trial' if payload['customer_id'].startswith('trial-') else 'paid',
                            source_payload_sha256=hashlib.sha256(raw).hexdigest(),
                            term_ends_at=self.args.term_date+'T12:00:00Z', expires_at=self.args.term_date+'T12:00:00Z',
                            issued_at='2025-12-18T12:00:00Z', enforce_expiry=True)
            selected['synthetic_key'] = self.secret('LOCAL-FIXTURE-MATRIX-'+install.upper())
            self.profiles.append(selected)
        self.private(self.state/'profiles.json', json.dumps([{k: v for k, v in p.items() if k != 'synthetic_key'} for p in self.profiles], indent=2))
        self.installations=[{k:v for k,v in p.items() if k!='synthetic_key'} for p in self.profiles]

    def control(self, group, **changes):
        return self.authority(group, '/control', changes)

    def authority(self, group, path, data=None):
        server = self.authorities[group]
        request = urllib.request.Request(server['url']+path, data=None if data is None else json.dumps(data).encode(),
            headers={'Authorization': 'Bearer '+server['token'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=self.ssl, timeout=10) as response:
            return json.load(response)

    def setup_resources(self):
        # Explicit small subnets avoid exhausting Docker's default pools. Refuse
        # any overlap with existing routes/networks instead of replacing them.
        existing = []
        for row in json.loads(subprocess.check_output(['ip', '-j', '-4', 'route'], text=True)):
            if row.get('dst') not in (None, 'default'):
                existing.append(ipaddress.ip_network(row['dst'], strict=False))
        networks = subprocess.check_output(['docker', 'network', 'ls', '-q'], text=True).split()
        for network in json.loads(subprocess.check_output(['docker', 'network', 'inspect', *networks], text=True)):
            existing += [ipaddress.ip_network(c['Subnet']) for c in (network['IPAM'].get('Config') or []) if c.get('Subnet') and ':' not in c['Subnet']]
        for index, profile in enumerate(self.profiles):
            subnet = ipaddress.ip_network('10.251.'+str(getattr(self.args,'subnet_base',144)+index)+'.0/24')
            if any(subnet.overlaps(used) for used in existing):
                raise RuntimeError('test subnet overlaps an existing route/network')
            self.docker('network', 'create', '--internal', '--subnet', str(subnet), '--label', self.label, self.run_id+'-'+profile['id'])
        for group, first in [('paid', 'license0'), ('trial', 'license2')]:
            token = self.secret(secrets.token_hex(32))
            env_file = self.state/(group+'-authority.env')
            self.private(env_file, 'FIXTURE_CONTROL_TOKEN='+token+'\n')
            name = self.run_id+'-'+group+'-authority'
            self.docker('run', '-d', '--name', name, '--label', self.label, '--network', self.run_id+'-'+first,
                '--network-alias', 'enterprise.basekick.net', '--env-file', env_file,
                '--user', str(os.getuid())+':'+str(os.getgid()),
                '-v', str(self.material)+':/fixture:ro', '-p', '127.0.0.1::443', '--memory', '192m', '--cpus', '1',
                '--pids-limit', '64', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', self.args.authority_image)
            if group == 'paid':
                self.docker('network', 'connect', '--alias', 'enterprise.basekick.net', self.run_id+'-license1', name)
            info=json.loads(self.docker('inspect',name).stdout)[0]
            address=info['NetworkSettings']['Networks'][self.run_id+'-'+first]['IPAddress']
            self.authorities[group] = {'name': name, 'url': 'https://'+address, 'token': token}
            deadline = time.monotonic()+20
            while True:
                try:
                    self.authority(group, '/stats')
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.25)
            profiles = {p['synthetic_key']: p for p in self.profiles if p['license_kind'] == group or (group == 'paid' and p['license_kind'] == 'paid')}
            self.control(group, profiles=profiles, strict_profiles=True, server_time=self.args.term_date+'T00:00:00Z', reset_events=True)
        self.private(self.state/'authorities.private.json', json.dumps(self.authorities, indent=2))
        self.s3_name = self.run_id+'-cold-store'
        folder = self.state/'cold-store'; folder.mkdir(mode=0o700)
        self.docker('run', '-d', '--name', self.s3_name, '--label', self.label, '--network', self.run_id+'-license0',
            '--network-alias', 'cold-store', '-p', '127.0.0.1::8333', '--memory', '512m', '--cpus', '.5',
            '-v', str(folder)+':/data', 'chrislusf/seaweedfs:4.47', 'server', '-dir=/data', '-s3', '-s3.port=8333',
            '-ip='+self.s3_name, '-ip.bind=0.0.0.0', '-master.volumeSizeLimitMB=64')
        for install in ('license1', 'license2'):
            self.docker('network', 'connect', '--alias', 'cold-store', self.run_id+'-'+install, self.s3_name)
        info=json.loads(self.docker('inspect',self.s3_name).stdout)[0]
        self.s3_url='http://'+info['NetworkSettings']['Networks'][self.run_id+'-license0']['IPAddress']+':8333'
        deadline = time.monotonic()+60
        while True:
            try:
                self.s3('/', 'GET'); break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.5)
        fixture = self.state/'synthetic.parquet'
        subprocess.run(['go', 'run', './scripts/license_docker/cold_fixture', str(fixture)], cwd=ROOT, check=True)
        for profile in self.profiles:
            bucket = profile['id']+'-cold'
            self.s3('/'+bucket, 'PUT')
            self.s3('/'+bucket+'/matrix/archive/license_test/synthetic_cold/2026/11/02/synthetic_cold_20261102_daily.parquet', 'PUT', fixture.read_bytes())

    def s3(self, path, method, data=None):
        with urllib.request.urlopen(urllib.request.Request(self.s3_url+path, data=data, method=method), timeout=10) as response:
            return response.status, response.read()

    def until(self, condition, timeout=25):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if self.watch_failures:
                raise RuntimeError('original-stack watchdog detected a change; no repairs attempted')
            if condition():
                return True
            time.sleep(.3)
        return False

    def setup_stack(self, profile):
        install = self.current = profile['id']
        admin, shared = self.secret(secrets.token_hex(32)), self.secret(secrets.token_hex(32))
        env = self.base_env(profile['synthetic_key'], admin, shared, install)
        env.update(SSL_CERT_FILE='/run/fixture-ca.crt', ARC_TIERED_STORAGE_MIGRATION_SCHEDULE='* * * * *',
            ARC_SCHEDULER_RETENTION_SCHEDULE='* * * * *', ARC_TIERED_STORAGE_SCAN_TIMEOUT='30s',
            ARC_COMPACTION_DAILY_MIN_FILES='1', ARC_COMPACTION_DAILY_SKIP_FILE_AGE_CHECK_DAYS='1',
            ARC_TIERED_STORAGE_COLD_ENABLED='true', ARC_TIERED_STORAGE_COLD_BACKEND='s3',
            ARC_TIERED_STORAGE_COLD_S3_BUCKET=install+'-cold', ARC_TIERED_STORAGE_COLD_S3_PREFIX='matrix/archive',
            ARC_TIERED_STORAGE_COLD_S3_REGION='us-east-1', ARC_TIERED_STORAGE_COLD_S3_ENDPOINT='http://cold-store:8333',
            ARC_TIERED_STORAGE_COLD_S3_ACCESS_KEY='local-test', ARC_TIERED_STORAGE_COLD_S3_SECRET_KEY='local-test',
            ARC_TIERED_STORAGE_COLD_S3_USE_SSL='false', ARC_TIERED_STORAGE_COLD_S3_PATH_STYLE='true')
        roles = [('w1','writer'), ('w2','writer')]
        roles += [('w3','writer'), ('r1','reader'), ('r2','reader')] if install == 'license0' else [('w3','compactor')]
        if install == 'license2':
            roles += [('r1','reader')]
        env['ARC_CLUSTER_SEEDS'] = ','.join('arc-license-'+install+'-'+r+':9100' for r, _ in roles if r.startswith('w'))
        names = []
        for role, cluster_role in roles:
            node = self.start_node(install, role, env, image=self.args.image, cluster_role=cluster_role,
                                   extra=('-v', str(self.material/'tls.crt')+':/run/fixture-ca.crt:ro'))
            self.wait(node)
            names.append(node)
        profile['nodes'], profile['leader'] = names, names[0]
        self.wait(names[0], '/api/v1/cluster', predicate=lambda body: body.get('node_count') == len(names))
        self.wait(names[0], '/ready/write')
        fps = []
        for node in names:
            pair = json.loads((Path(self.nodes[node]['data'])/'license_cache.json').read_text())
            payload = json.loads(base64.b64decode(pair['license_file']))
            fps.append(payload['machine_fingerprint'])
            self.record('exact_signed_capability_profile:'+self.nodes[node]['role'], all(payload.get(k) == profile[k] for k in ('tier','features','max_cores','max_machines')),
                        {k: payload.get(k) for k in ('tier','features','max_cores','max_machines')})
        profile['fingerprints'] = fps
        self.private(self.state/'fingerprints.private.json',json.dumps({p['id']:p['fingerprints'] for p in self.profiles if p.get('fingerprints')},indent=2))
        self.write_probe(profile, 'initial', count=20)
        self.api(names[0], '/api/v1/write/line-protocol', f'private_events value=1i {time.time_ns()}\n')
        self.until(lambda: self.query_count(names[0])[1].get('columns') == ['n'])
        self.current_features = set(profile['features'])
        self.rbac(names[0])
        # Explicitly exercise configured CQ, retention and governance rather
        # than treating a feature bit or a running flag as successful execution.
        cq = self.api(names[0], '/api/v1/continuous_queries/', {'name':'matrix-cq','database':'license_test','source_measurement':'events',
            'destination_measurement':'matrix_aggregate','interval':'1m','is_active':True,
            'query':'SELECT max(time) AS time,count(*) AS event_count FROM license_test.events WHERE time >= {start_time} AND time < {end_time} HAVING count(*) > 0'})
        self.record('cq_definition_created', cq[0] == 201, cq)
        if cq[0] == 201:
            profile['cq_id'] = cq[1]['id']
        policy = self.api(names[0], '/api/v1/retention/', {'name':'matrix-retention','database':'license_test','measurement':'retention_probe',
            'retention_days':1,'buffer_days':0,'is_active':True})
        self.record('retention_definition_created', policy[0] == 201, policy)
        if policy[0] == 201:
            profile['retention_id'] = policy[1]['id']
        self.current_features = set(profile['features'])
        saved = json.loads((self.state/install/'rbac.private.json').read_text())
        # Suite.rbac creates the token's governance policy when this feature is
        # enabled. Do not insert it a second time and misclassify a duplicate.
        restricted = self.api(names[0], '/api/v1/query', {'sql':'SELECT record_id,value FROM events ORDER BY value LIMIT 10'}, token=self.secret(saved['token']))
        self.record('governance_row_cap_enforced', restricted[0] == 200 and restricted[1].get('row_count') == 1, restricted)

    def write_probe(self, profile, label, count=1):
        node = profile['leader']; ids = [label+'-'+secrets.token_hex(8) for _ in range(count)]
        stamp = time.time_ns()
        code, body = self.api(node, '/api/v1/write/line-protocol', ''.join(f'events,record_id={identity} value={i}i {stamp+i}\n' for i, identity in enumerate(ids)))
        if code == 204:
            self.expected_ids[profile['id']].update(ids)
        self.private(self.state/'acknowledged-ids.private.json', json.dumps({k: sorted(v) for k,v in self.expected_ids.items()}, indent=2))
        self.record('write_ack:'+label, code == 204, (code, body))

    def storage_snapshot(self, node):
        with sqlite3.connect('file:'+self.nodes[node]['data']+'/arc.db?mode=ro', uri=True, timeout=3) as db:
            db.execute('BEGIN')
            integrity = db.execute('PRAGMA quick_check').fetchone()[0]
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            histories = {}
            config = {}
            for name in tables:
                quoted = '"'+name.replace('"','""')+'"'
                columns = [r[1] for r in db.execute('PRAGMA table_info('+quoted+')')]
                if name.startswith('rbac_') or name in ('tiering_policies','retention_policies','continuous_queries','governance_policies'):
                    stable = [c for c in columns if not c.startswith('last_') and c != 'updated_at']
                    selected = ','.join('"'+c.replace('"','""')+'"' for c in stable)
                    rows = sorted(map(repr,db.execute('SELECT '+selected+' FROM '+quoted).fetchall()))
                    config[name] = {'rows':len(rows),'columns':stable,'sha256':hashlib.sha256(repr(rows).encode()).hexdigest(),
                        'row_hashes':sorted(hashlib.sha256(row.encode()).hexdigest() for row in rows)}
                if name == 'audit_logs' or 'execution' in name or name == 'query_history':
                    immutable = []
                    for row in db.execute('SELECT * FROM '+quoted).fetchall():
                        values = dict(zip(columns,row))
                        if values.get('status') in ('running','pending','started'):
                            continue
                        immutable.append(hashlib.sha256(repr(row).encode()).hexdigest())
                    histories[name] = sorted(immutable)
            db.rollback()
        return {'integrity':integrity, 'config':config, 'histories':histories}

    def exercise_jobs(self, profile, expired):
        leader=profile['leader'];now=dt.datetime.now(UTC)
        stamp=time.time_ns();identity=secrets.token_hex(8)
        feed=self.api(leader,'/api/v1/write/line-protocol',
            f'retention_probe,age=old,record_id={identity} value=1i {stamp-3*24*3600*10**9}\n'
            f'retention_probe,age=current,record_id={identity} value=1i {stamp}\n')
        self.record('retention_fixture_feed',feed[0]==204,feed)
        def retention_rows():
            code,body=self.api(leader,'/api/v1/query',{'sql':"SELECT age,count(*) AS n FROM retention_probe WHERE record_id='"+identity+"' GROUP BY age ORDER BY age"})
            if code!=200 or body.get('columns')!=['age','n']:return None
            return {row[0]:row[1] for row in body.get('data',[])}
        visible=self.until(lambda:retention_rows()=={'old':1,'current':1},timeout=8)
        self.record('retention_fixture_visible',True if visible else None,retention_rows(),
            note='Old rows can be removed by a concurrent scheduler; absent setup evidence is inconclusive, never a policy pass.')
        if profile.get('cq_id'):
            cq=self.api(leader,f"/api/v1/continuous_queries/{profile['cq_id']}/execute",{
                'start_time':(now-dt.timedelta(minutes=10)).isoformat(),'end_time':now.isoformat()})
            if expired:
                self.record('manual_cq_execution_after_expiry',observed=cq,
                    note='Manual execution has no license middleware in current code; scheduler shutdown is asserted separately, not inferred from this API.')
            else:
                self.record('cq_execution_completes',cq[0]==200 and cq[1].get('status')=='completed',cq)
        if profile.get('retention_id'):
            retention=self.api(leader,f"/api/v1/retention/{profile['retention_id']}/execute",{'dry_run':False,'confirm':True})
            if expired:
                self.record('manual_retention_execution_after_expiry',observed=retention,
                    note='Manual execution and licensed background scheduling are separate code paths; record this behavior without inventing an HTTP403 requirement.')
            else:
                self.record('retention_execution_completes',retention[0]==200,retention)
            correct=self.until(lambda:retention_rows()=={'current':1},timeout=8)
            self.record('retention_policy_effects',correct if visible else None,retention_rows(),{'current':1},
                note='The acknowledged current row must survive and the eligible old row must disappear; HTTP200 alone is insufficient.')

    def prepare_pending_candidate(self, profile):
        self.current=profile['id'];leader=profile['leader'];measurement='migration_pending'
        stamp=time.time_ns()-3*24*3600*10**9
        for first in (0,15):
            write=self.api(leader,'/api/v1/write/line-protocol',''.join(f'{measurement},record_id=p{i} value={i}i {stamp+i}\n' for i in range(first,first+15)))
            self.record('pending_migration_fixture_ack',write[0]==204,write)
            time.sleep(1)
        def compactor_node():
            cluster=self.api(leader,'/api/v1/cluster')[1]
            holder=cluster.get('active_compactor',{}).get('node_id')
            selected=next((n for n in profile['nodes'] if self.nodes[n]['hostname']==holder),None)
            if selected:return selected
            # Without licensed writer failover there is no WFM assignment;
            # the registered dedicated-compactor role is the execution target.
            dedicated=[n for n in cluster.get('nodes',[]) if n.get('role')=='compactor' and n.get('state')=='healthy']
            if len(dedicated)==1:
                return next((n for n in profile['nodes'] if self.nodes[n]['hostname']==dedicated[0]['id']),None)
        target=compactor_node()
        if target is None:
            self.record('background_migration_evidence_inconclusive',observed='No active compactor available to create candidate')
            return
        self.until(lambda:self.query_count(target,measurement)[1].get('columns')==['n'])
        compact=self.api(target,'/api/v1/compaction/trigger?tier=daily&database=license_test&measurement='+measurement,{})
        self.record('pending_candidate_compaction_requested',compact[0] in (200,202),compact)
        if compact[0] not in (200,202):return
        cycle_id=compact[1].get('cycle_id')
        done=self.until(lambda:self.api(target,'/api/v1/compaction/cycles/'+str(cycle_id))[1].get('status')=='completed',timeout=60)
        self.record('pending_candidate_compaction_completed',done)
        self.api(leader,'/api/v1/tiering/scan',{})
        preview=None
        def eligible():
            nonlocal preview
            preview=self.api(leader,'/api/v1/tiering/migrate',{'database':'license_test','measurement':measurement,'dry_run':True})
            return preview[0]==200 and preview[1].get('would_migrate',0)>0
        profile['pending_candidate_ready']=self.until(eligible,timeout=25)
        self.record('real_eligible_candidate_remains_on_day10',True if profile['pending_candidate_ready'] else None,preview,
            note='INCONCLUSIVE if fixture cannot establish an eligible candidate; compaction completion alone is insufficient.')

    def observe_background(self, profiles, expired=False, check_migration=True):
        before={}
        for p in profiles:
            leader=p['leader'];snap=self.storage_snapshot(leader)
            before[p['id']]={'history':{k:v for k,v in snap['histories'].items() if 'execution' in k},
                'tier_ticks':self.docker('logs',leader).stdout.count('Scheduled migration cycle starting')}
            if not expired:
                cq=self.api(leader,f"/api/v1/continuous_queries/{p['cq_id']}/executions?limit=100")
                before[p['id']]['cq_ids']={row.get('execution_id') for row in cq[1].get('executions',[])} if cq[0]==200 else None
        # Cron uses real application time; this covers at least one minute tick.
        deadline=time.monotonic()+65
        while time.monotonic()<deadline:
            if self.watch_failures:raise RuntimeError('original-stack watchdog detected a change')
            time.sleep(1)
        for p in profiles:
            self.current=p['id'];leader=p['leader'];snap=self.storage_snapshot(leader)
            history={k:v for k,v in snap['histories'].items() if 'execution' in k}
            if expired:
                self.record('expired_background_execution_stopped',history==before[p['id']]['history'],
                    {'before':{k:len(v) for k,v in before[p['id']]['history'].items()},'after':{k:len(v) for k,v in history.items()}})
            else:
                logs=self.docker('logs',leader).stdout
                self.record('background_tier_tick_observed',logs.count('Scheduled migration cycle starting')>before[p['id']]['tier_ticks'])
                if check_migration and p.get('pending_candidate_ready'):
                    with sqlite3.connect('file:'+self.nodes[leader]['data']+'/arc.db?mode=ro',uri=True) as db:
                        tiers=db.execute('SELECT tier FROM tier_files WHERE measurement=?',('migration_pending',)).fetchall()
                        migrated=db.execute('SELECT COUNT(*) FROM tier_migrations WHERE file_path LIKE ?',('%/migration_pending/%',)).fetchone()[0]
                    self.record('day10_background_candidate_not_migrated',bool(tiers) and all(r[0]=='hot' for r in tiers) and migrated==0,{'tiers':tiers,'migration_history':migrated})
                elif check_migration:
                    self.record('background_migration_evidence_inconclusive',observed='No proven eligible candidate; cron execution alone cannot prove migration refusal')
                cq=self.api(leader,f"/api/v1/continuous_queries/{p['cq_id']}/executions?limit=10")
                executions=cq[1].get('executions',[]) if cq[0]==200 else []
                old_ids=before[p['id']]['cq_ids']
                self.record('cq_background_execution_observed',old_ids is not None and any(str(r.get('execution_id','')).startswith('cq-sched-') and
                    r.get('execution_id') not in old_ids and r.get('status')=='completed' and r.get('records_written',0)>0 for r in executions),cq,
                    note='Requires a newly completed scheduled execution absent from the pre-window snapshot.')

    def confirm_authority_phase(self, group, profiles, stamp):
        boundary = dt.datetime.fromisoformat(stamp.replace('Z','+00:00'))
        def received():
            events = self.authority(group, '/stats')['events']
            for profile in profiles:
                seen = {e['fingerprint'] for e in events if e.get('profile') == profile['id'] and e.get('effective_server_time') and
                    dt.datetime.fromisoformat(e['effective_server_time']) >= boundary and (e.get('successful_verdict') or e.get('rejection_reason') == 'license has expired')}
                if not set(profile['fingerprints']).issubset(seen):
                    return False
            return True
        return self.until(received, timeout=35)

    def sample(self, profile, day, expired=False, expected_status=None):
        self.current = profile['id']; leader = profile['leader']; nodes = profile['nodes']
        evidence = {'phase':self.phase_name,'installation':self.current,'observed_at':dt.datetime.now(UTC).isoformat(),'day':day,'nodes':{}}
        for node in nodes:
            evidence['nodes'][node] = {'health':self.api(node,'/health'), 'ready':self.api(node,'/ready'),
                'ready_write':self.api(node,'/ready/write'), 'cluster':self.api(node,'/api/v1/cluster'),
                'data_query':self.query_count(node)}
        healths = [v['health'][1].get('license',{}) for v in evidence['nodes'].values()]
        if expired:
            self.record('license_no_longer_valid', all(h.get('status') in ('expired','unlicensed') for h in healths), healths)
        elif expected_status:
            self.record('license_expected_status', all(h.get('status') == expected_status for h in healths), healths, expected_status)
        for feature,path in [('rbac','/api/v1/rbac/organizations'),('tiering','/api/v1/tiering/status'),('query_management','/api/v1/queries/active'),
                             ('query_governance','/api/v1/governance/policies'),('audit_logging','/api/v1/audit/logs?limit=3')]:
            actual = self.api(leader,path); expected = 403 if expired else 200
            evidence[feature] = actual
            self.record(feature+'_feature_access', actual[0] == expected, actual, expected)
        mutation = self.api(leader,'/api/v1/rbac/organizations',{'name':'phase-'+self.phase_name+'-'+secrets.token_hex(4)})
        allowed = not expired and day < 9
        self.record('rbac_management_policy', mutation[0] == (201 if allowed else 403), mutation)
        # Management probes before day9 intentionally create config. Capture the
        # stable baseline only once management becomes read-only.
        saved = json.loads((self.state/self.current/'rbac.private.json').read_text())
        scoped = self.secret(saved['token'])
        grant = self.api(leader, f"/api/v1/auth/tokens/{saved['token_id']}/teams", {'team_id':saved['team']})
        if not allowed:
            self.record('membership_grants_refused',grant[0] == 403,grant)
        allowed_read = self.api(leader,'/api/v1/query',{'sql':'SELECT count(*) AS n FROM events'},token=scoped)
        denied_read = self.api(leader,'/api/v1/query',{'sql':'SELECT count(*) AS n FROM private_events'},token=scoped)
        self.record('data_rbac_grants_and_denials_preserved', allowed_read[0] == 200 and denied_read[0] == 403, {'allowed':allowed_read,'denied':denied_read})
        governed=self.api(leader,'/api/v1/query',{'sql':'SELECT record_id,value FROM events ORDER BY value LIMIT 10'},token=scoped)
        self.record('governance_effective_license_policy',governed[0]==200 and governed[1].get('row_count')==(10 if expired else 1),
            governed,10 if expired else 1,note='Configured governance metadata is retained; licensed query-governance functionality should become dormant in OSS. Existing RBAC data authorization is checked separately.')
        migrate = self.api(leader,'/api/v1/tiering/migrate',{'database':'license_test','measurement':'no_candidates'})
        self.record('migration_admission_policy',migrate[0] == (403 if expired or day >= 10 else 200),migrate)
        cold = self.query_count(leader,'synthetic_cold')
        self.record('cold_rows_always_readable',cold[0] == 200 and cold[1].get('columns') == ['n'] and self.count(cold[1]) == 30,cold)
        self.exercise_jobs(profile,expired)
        self.write_probe(profile,self.phase_name)
        def intact():
            result = self.api(leader,'/api/v1/query',{'sql':'SELECT record_id FROM events'})
            if result[0] != 200 or result[1].get('columns') != ['record_id']:
                return False
            rows = result[1].get('data',[])
            ids = [r[0] if isinstance(r,list) else r['record_id'] for r in rows]
            return len(ids) == len(set(ids)) == len(self.expected_ids[self.current]) and set(ids) == self.expected_ids[self.current]
        self.record('every_acknowledged_id_present_once',self.until(intact))
        time.sleep(1)
        for node in nodes:
            snap = self.storage_snapshot(node)
            baseline = self.baselines.get(node)
            self.record('sqlite_integrity:'+self.nodes[node]['role'],snap['integrity']=='ok')
            if baseline:
                retained = all(set(rows).issubset(set(snap['histories'].get(table,[]))) for table,rows in baseline['histories'].items())
                self.record('baseline_history_rows_retained:'+self.nodes[node]['role'],retained,
                    {table:len(rows) for table,rows in snap['histories'].items()})
                if day >= 9 or expired:
                    retained_config=all(set(row['row_hashes']).issubset(set(snap['config'].get(table,{}).get('row_hashes',[]))) for table,row in baseline['config'].items())
                    self.record('baseline_config_rows_retained:'+self.nodes[node]['role'],retained_config,
                        {'before':baseline['config'],'after':snap['config']},
                        note='Permit pending replicated additions; require every original stable configuration row unchanged.')
            if not baseline or (not expired and day < 9):
                self.baselines[node] = snap
        cluster = evidence['nodes'][leader]['cluster'][1]
        if day >= 8 and not expired:
            serving = collections.defaultdict(list)
            for node, row in evidence['nodes'].items():
                role = next((n['role'] for n in cluster.get('nodes',[]) if n['id']==self.nodes[node]['hostname']), 'unknown')
                if row['data_query'][0] == 200 and row['data_query'][1].get('columns') == ['n']:
                    serving[role].append(self.nodes[node]['hostname'])
            self.record('only_one_data_serving_endpoint_per_role',all(len(v)<=1 for v in serving.values()),dict(serving),
                note='Direct per-node data operations; membership labels are recorded separately.')
            if 'writer_failover' in profile['features']:
                self.record('writer_failover_worker_stopped',not cluster.get('writer_failover',{}).get('running',True),cluster.get('writer_failover'))
            self.record('load_distribution_state',observed=cluster.get('router'),note='Router status alone is not proof of traffic distribution; direct reader probes above show serving endpoints.')
        if expired:
            standalone = [node for node,row in evidence['nodes'].items() if row['cluster'][0] == 200 and not row['cluster'][1].get('enabled',True) and row['ready_write'][0] == 200]
            raft_off = all(not row['cluster'][1].get('raft',{}).get('enabled',False) for row in evidence['nodes'].values())
            self.record('one_standalone_oss_owner',len(standalone)==1,standalone)
            self.record('raft_stopped_everywhere',raft_off)
            fenced = [node for node,row in evidence['nodes'].items() if row['ready_write'][0] != 200 and row['data_query'][0] != 200]
            self.record('all_other_peers_fenced',len(fenced)==len(nodes)-1,fenced)
        self.private(self.state/('phase-'+self.phase_name+'-'+self.current+'.json'),json.dumps(self.redact(evidence),indent=2))
        self.private(self.state/'metadata-baselines.json',json.dumps(self.baselines,indent=2))

    def resume_stacks(self):
        self.authorities=json.loads((self.state/'authorities.private.json').read_text())
        for server in self.authorities.values():self.secret(server['token'])
        requested=dt.datetime.fromisoformat(self.args.term_date+'T00:00:00+00:00')
        for group in ('paid','trial'):
            if requested<=authority_now(self.authority(group,'/stats')):
                raise RuntimeError('resume term date must advance both test authority clocks; no authority was changed')
        fingerprints=json.loads((self.state/'fingerprints.private.json').read_text())
        for p in self.profiles:
            p['nodes']=[n for n,v in self.nodes.items() if v['install']==p['id']]
            p['leader']=next(n for n in p['nodes'] if self.nodes[n]['role']=='w1')
            p['fingerprints']=fingerprints.get(p['id'],[])
            if len(set(p['fingerprints']))!=len(p['nodes']) or not p['nodes']:
                raise RuntimeError('retained fingerprint manifest does not cover every expected node; no authority was changed')
        self.expected_ids.update({k:set(v) for k,v in json.loads((self.state/'acknowledged-ids.private.json').read_text()).items()})
        self.phase_name='synthetic-renewal'
        for group in ('paid','trial'):
            profiles={p['synthetic_key']:p for p in self.profiles if p['license_kind']==group}
            self.control(group,profiles=profiles,mode='valid',activation_mode='valid',server_time=self.args.term_date+'T00:00:00Z')
            for p in self.profiles:
                if p['license_kind']!=group:continue
                p['cq_id'],p['retention_id']=1,1
                self.current=p['id']
                self.record('renewal_restores_existing_feature_gate',self.until(lambda:self.api(p['leader'],'/api/v1/queries/active')[0]==200))
                for node in p['nodes']:self.baselines[node]=self.storage_snapshot(node)
        self.record('renewal_limitation',observed='Feature recovery only: the current code never completed the required OSS handoff, so this does not prove inverse handoff reconciliation.')

    def focus_review(self):
        self.phase_name='review-oracles'
        for p in self.profiles:
            self.current=p['id'];self.write_probe(p,'review-oracles');self.exercise_jobs(p,False)
            self.write_probe(p,'review-background')
        self.observe_background(self.profiles,check_migration=False)
        origin=dt.date.fromisoformat(self.args.term_date)
        for group,days in [('paid',15),('trial',1)]:
            stamp=(origin+dt.timedelta(days=days)).isoformat()+'T12:00:00Z'
            self.control(group,server_time=stamp)
            members=[p for p in self.profiles if p['license_kind']==group]
            self.current=group+'-authority'
            self.record('final_expired_phase_received',self.confirm_authority_phase(group,members,stamp))
        for p in self.profiles:
            self.current=p['id']
            self.record('final_feature_gate_closed',self.api(p['leader'],'/api/v1/queries/active')[0]==403)
            cold=self.query_count(p['leader'],'synthetic_cold')
            self.record('final_cold_data_preserved',cold[0]==200 and cold[1].get('columns')==['n'] and self.count(cold[1])==30,cold)

    def run(self):
        watch = threading.Thread(target=self.watch_originals,daemon=True);watch.start()
        try:
            self.profiles_from_verified_cache()
            if self.args.resume:self.resume_stacks()
            else:
                self.setup_resources()
                for profile in self.profiles:self.setup_stack(profile)
            if self.args.focus_review:
                if not self.args.resume:raise RuntimeError('focused recheck requires existing retained stacks')
                self.focus_review();return
            paid = [p for p in self.profiles if p['license_kind']=='paid']; trial = next(p for p in self.profiles if p['license_kind']=='trial')
            origin=dt.date.fromisoformat(self.args.term_date)
            def stamp_on(day,clock):return (origin+dt.timedelta(days=day)).isoformat()+'T'+clock+'Z'
            stages = [('before-expiry',stamp_on(0,'11:00:00'),0,'active'),('expiration-day',stamp_on(0,'13:00:00'),0,'grace_period'),
                ('day1',stamp_on(1,'00:00:05'),1,'grace_period'),('day7',stamp_on(7,'12:00:00'),7,'grace_period'),
                ('day8',stamp_on(8,'00:00:05'),8,'grace_period'),('day9',stamp_on(9,'00:00:05'),9,'grace_period'),
                ('day10',stamp_on(10,'00:00:05'),10,'grace_period'),('day14',stamp_on(14,'23:58:00'),14,'grace_period'),
                ('day15',stamp_on(15,'00:00:05'),15,None)]
            for label,stamp,day,status in stages:
                self.phase_name=label;self.current='paid-authority'
                self.control('paid',server_time=stamp)
                self.record('all_paid_nodes_received_phase',self.confirm_authority_phase('paid',paid,stamp))
                for profile in paid:self.sample(profile,day,expired=day==15,expected_status=status)
                if day==10:
                    for profile in paid:self.prepare_pending_candidate(profile)
                    self.observe_background(paid)
                if day==15:self.observe_background(paid,expired=True)
                self.current=trial['id']
                h=self.api(trial['leader'],'/health')[1].get('license',{})
                self.record('paid_clock_does_not_advance_trial',h.get('status')=='active' and h.get('evaluated_at','').startswith(self.args.term_date),h)
                if day==14:
                    self.phase_name='paid-local-cutoff';self.current='paid-authority'
                    anchor=stamp_on(14,'23:59:50');self.control('paid',server_time=anchor)
                    self.record('paid_pre_cutoff_anchor_received',self.confirm_authority_phase('paid',paid,anchor))
                    self.control('paid',mode='503',activation_mode='503')
                    time.sleep(.5) # let requests admitted before outage finish
                    accepted=self.authority('paid','/stats').get('successful_verdict_total')
                    self.record('paid_pre_cutoff_still_valid',all(self.api(n,'/health')[1].get('license',{}).get('status')=='grace_period' for p in paid for n in p['nodes']))
                    expired=self.until(lambda:all(self.api(n,'/health')[1].get('license',{}).get('status')=='expired' for p in paid for n in p['nodes']),timeout=25)
                    after=self.authority('paid','/stats').get('successful_verdict_total')
                    self.record('paid_cutoff_from_elapsed_time_without_new_grant',expired and accepted==after if accepted is not None and after is not None else None,
                        note='Uses the cumulative counter, independent of rolling diagnostic history; old authorities without this counter are inconclusive.')
                    for p in paid:
                        self.current=p['id']
                        self.record('paid_local_cutoff_feature_gate_closed',self.api(p['leader'],'/api/v1/queries/active')[0]==403)
                    self.control('paid',mode='valid',activation_mode='valid')
            self.phase_name='trial-exact-cutoff';self.current=trial['id']
            stamp=stamp_on(0,'11:59:50');self.control('trial',server_time=stamp)
            self.record('all_trial_nodes_received_pre_expiry_anchor',self.confirm_authority_phase('trial',[trial],stamp))
            anchors={n:self.api(n,'/health') for n in trial['nodes']}
            self.control('trial',mode='503',activation_mode='503')
            time.sleep(.5)
            accepted=self.authority('trial','/stats').get('successful_verdict_total')
            self.record('trial_pre_cutoff_still_active',all(self.api(n,'/health')[1].get('license',{}).get('status')=='active' for n in trial['nodes']))
            self.record('trial_expires_from_elapsed_anchor',self.until(lambda:all(self.api(n,'/health')[1].get('license',{}).get('status')=='expired' for n in trial['nodes']),timeout=25),
                {'last_anchors':anchors,'observed_at':dt.datetime.now(UTC).isoformat()},note='No successful authority response can advance the clock during this window.')
            after=self.authority('trial','/stats').get('successful_verdict_total')
            self.record('trial_no_successful_refresh_during_cutoff',accepted==after if accepted is not None and after is not None else None,
                note='Cumulative verdict count must remain unchanged; eviction/reset of diagnostic events cannot authorize a pass.')
            self.sample(trial,0,expired=True)
            self.observe_background([trial],expired=True)
            for day in (1,7,8,14):
                self.phase_name='trial-day'+str(day);self.current=trial['id']
                stamp=stamp_on(day,'12:00:00')
                self.control('trial',mode='valid',activation_mode='valid',server_time=stamp)
                self.record('trial_authority_rejected_expired_key',self.confirm_authority_phase('trial',[trial],stamp))
                self.sample(trial,day,expired=True)
        except Exception as error:
            self.record('harness_exception',False,str(error),note='Setup/runtime failure; do not classify as a product behavior without investigation.')
            raise
        finally:
            self.watch_stop.set();watch.join(timeout=15)
            final=self.original_snapshot()
            self.private(self.state/'original-after.json',json.dumps(final,indent=2))
            self.private(self.state/'protection.json',json.dumps({'samples':self.watch_samples,'failures':self.watch_failures,'final_unchanged':final==self.original},indent=2))
            self.record('original_stacks_and_observer_unchanged',not self.watch_failures and final==self.original,{'watchdog_samples':self.watch_samples})
            for profile in self.profiles:
                if profile.get('nodes'):
                    self.collect(profile['id'])
            for group in self.authorities:
                self.private(self.state/('authority-'+group+'-events.json'),json.dumps(self.redact(self.authority(group,'/stats')),indent=2))
            self.write_report()
            print('New stacks and both authorities are retained; no automatic stop or removal.',flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',required=True);p.add_argument('--material',required=True);p.add_argument('--live-state',required=True)
    p.add_argument('--run-id',default='arc-license-matrix');p.add_argument('--image',default='arc-license-matrix:fast')
    p.add_argument('--authority-image',default='arc-license-matrix-authority:local')
    p.add_argument('--resume',action='store_true',help='renew synthetic grants and repeat on the same running new stacks')
    p.add_argument('--term-date',default='2026-01-01',help='synthetic nominal UTC date; must move forward for a resume')
    p.add_argument('--focus-review',action='store_true',help='recheck retention outcomes and newly scheduled CQs on retained stacks')
    suite=Matrix(p.parse_args());suite.run()
    raise SystemExit(any(r['result']=='FAIL' for r in suite.results))


if __name__=='__main__':main()
