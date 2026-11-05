#!/usr/bin/env python3
"""Suspension/reactivation tests against retained synthetic installations only."""
import argparse
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import threading
import time

from run import Suite, UTC
from three_stacks import Matrix, authority_now


def failover_configuration(logs):
    """Monitoring runs without failover entitlement; read the actual startup flag."""
    flags=[]
    for line in logs.splitlines():
        try:row=json.loads(line)
        except (ValueError,TypeError):continue
        if row.get('message')=='Writer primary election initialized' and isinstance(row.get('auto_failover'),bool):
            flags.append(row['auto_failover'])
    return flags[-1] if flags else None


class Normalization(Matrix):
    def __init__(self,args):
        Suite.__init__(self,args)
        self.fixture=Path(args.fixture_state).resolve()
        if (self.state/'report.json').exists():raise RuntimeError('use a new output directory')
        self.nodes=json.loads((self.fixture/'nodes.private.json').read_text())
        for row in self.nodes.values():self.secret(row['token'])
        self.authorities=json.loads((self.fixture/'authorities.private.json').read_text())
        for row in self.authorities.values():self.secret(row['token'])
        self.material=Path(args.material).resolve()/'private'
        self.ssl=ssl.create_default_context(cafile=str(self.material/'tls.crt'))
        self.expected_ids=collections.defaultdict(set,{k:set(v) for k,v in json.loads((self.fixture/'acknowledged-ids.private.json').read_text()).items()})
        self.profiles=json.loads((self.fixture/'profiles.json').read_text())
        fingerprints=json.loads((self.fixture/'fingerprints.private.json').read_text())
        self.phase_name='preflight';self.phase_marker='';self.phase_started_ns=0
        self.baselines={};self.watch_stop=threading.Event();self.watch_failures=[];self.watch_samples=0
        self.oss_tokens={};self.probe=None;self.probe_id=None;self.probe_fp=None
        stats={g:self.authority(g,'/stats') for g in ('paid','trial')}
        for p in self.profiles:
            group='trial' if p['license_kind']=='trial' else 'paid'
            p['_key']=next(key for key,value in stats[group]['state']['profiles'].items() if value.get('profile_id')==p['id'])
            if not p['_key'].startswith('LOCAL-FIXTURE-'):raise RuntimeError('refuse a non-synthetic key')
            self.secret(p['_key']);self.secret(p['_key'][:12])
            p['nodes']=[name for name,row in self.nodes.items() if row['install']==p['id']]
            p['leader']=next(name for name in p['nodes'] if self.nodes[name]['role']=='w1')
            p['fingerprints']=fingerprints[p['id']]
            if len(set(p['fingerprints']))!=len(p['nodes']):raise RuntimeError('incomplete participant manifest')
            current=stats[group]['state']['profiles'][p['_key']]
            epochs=stats[group]['state'].get('activation_epochs',{}).get(p['_key'],{})
            p['mode']=p['activation_mode']='valid';p['reactivation_epoch']=max([current.get('reactivation_epoch',0),*epochs.values()])
            p['cq_id']=p['retention_id']=1
            token=json.loads((self.fixture/p['id']/'rbac.private.json').read_text())['token'];self.secret(token)
        self.installations=[{k:p[k] for k in ('id','tier','license_kind','features','max_cores','max_machines','nodes')} for p in self.profiles]
        originals=self.original_snapshot()
        required=json.loads((Path(args.live_state).parent/'natural-expiry/startup.json').read_text())['nodes']
        required={r['container'] for r in required}|{'arc-license-live-cold-store','arc-license-live-natural-expiry-observer'}
        if not required.issubset(originals) or not all(originals[n]['running'] for n in required):raise RuntimeError('original services are not ready')
        self.protected_names=list(originals)+list(self.nodes)+[self.run_id+'-cold-store']
        self.protected_before=self.protected_snapshot()
        for name,row in self.nodes.items():
            if self.protected_before[name]['image']!=row['image_id']:raise RuntimeError('retained Arc image drift')
        self.private(self.state/'protected-before.json',json.dumps(self.protected_before,indent=2))

    def protected_snapshot(self):
        rows=json.loads(self.docker('inspect',*self.protected_names).stdout)
        return {r['Name'].lstrip('/'):{'id':r['Id'],'image':r['Image'],'started_at':r['State']['StartedAt'],
             'restart_count':r['RestartCount'],'running':r['State']['Running']} for r in rows}

    def watch_originals(self):
        while not self.watch_stop.is_set():
            try:
                current=self.protected_snapshot();self.watch_samples+=1
                if current!=self.protected_before:self.watch_failures.append({'time':dt.datetime.now(UTC).isoformat(),'actual':current})
            except Exception as error:self.watch_failures.append({'time':dt.datetime.now(UTC).isoformat(),'error':str(error)})
            self.watch_stop.wait(2)

    def write_probe(self,p,label,count=1):
        super().write_probe(p,label,count)
        self.private(self.fixture/'acknowledged-ids.private.json',json.dumps({k:sorted(v) for k,v in self.expected_ids.items()},indent=2))

    def authority_profiles(self,group):
        allowed=('id','profile_id','tier','features','max_cores','max_machines','license_kind','term_ends_at','expires_at','issued_at',
                 'enforce_expiry','mode','activation_mode','reactivation_epoch','reactivation_reason','test_phase')
        return {p['_key']:{k:p[k] for k in allowed if k in p} for p in self.profiles if ('trial' if p['license_kind']=='trial' else 'paid')==group}

    def set_phase(self,label,changes=None,anchor=None):
        self.phase_name=label;self.phase_marker=label+'-'+secrets.token_hex(5);self.phase_started_ns=time.time_ns()
        for p in self.profiles:
            p.update((changes or {}).get(p['id'],{}));p['test_phase']=self.phase_marker
        for group in ('paid','trial'):
            fields={'profiles':self.authority_profiles(group),'mode':'valid','activation_mode':'valid'}
            if anchor:fields['server_time']=anchor
            self.control(group,**fields)

    def events(self,p):
        group='trial' if p['license_kind']=='trial' else 'paid'
        return [e for e in self.authority(group,'/stats')['events'] if e.get('profile')==p['id'] and e.get('test_phase')==self.phase_marker]

    def request_totals(self,p,fp=None):
        group='trial' if p['license_kind']=='trial' else 'paid';state=self.authority(group,'/stats')['state']
        if 'request_totals' not in state:raise RuntimeError('test authority lacks cumulative request counters')
        counts=state['request_totals'].get(p['_key'],{})
        return counts.get(fp,{'verify':0,'activate':0}) if fp else {f:counts.get(f,{'verify':0,'activate':0}) for f in p['fingerprints']}

    def connect_saved_networks(self,container,networks):
        attached=json.loads(self.docker('inspect',container).stdout)[0]['NetworkSettings']['Networks']
        for network,row in networks.items():
            if network in attached:continue
            options=['--ip',row['IPAddress']]
            for alias in row.get('Aliases') or []:options+=['--alias',alias]
            self.docker('network','connect',*options,network,container)

    def refresh_authorities(self):
        # Resolve locally before disturbing either running test authority.
        self.docker('image','inspect',self.args.refresh_authority_image)
        for group,first in [('paid','license0'),('trial','license2')]:
            server=self.authorities[group]
            if server['name']!=self.run_id+'-'+group+'-authority':raise RuntimeError('unexpected authority name')
            old=json.loads(self.docker('inspect',server['name']).stdout)[0]
            if not self.require_owned('container',server['name']):raise RuntimeError('missing test authority')
            snapshot=self.authority(group,'/stats');clock=authority_now(snapshot)
            self.persist_authority_state(group)
            saved=self.state/('authority-initial-'+group+'.json');self.private(saved,json.dumps(snapshot['state']))
            network=self.run_id+'-'+first
            address=old['NetworkSettings']['Networks'][network]['IPAddress']
            backup=server['name']+'-rollback-'+self.case_id;replacement=None
            try:
                self.docker('stop',old['Id'])
                for attached in old['NetworkSettings']['Networks']:
                    self.docker('network','disconnect',attached,old['Id'])
                self.docker('rename',old['Id'],backup)
                replacement=self.docker('create','--name',server['name'],'--label',self.label,'--network',network,'--ip',address,'--network-alias','enterprise.basekick.net',
                    '--user',str(os.getuid())+':'+str(os.getgid()),'--env-file',self.fixture/(group+'-authority.env'),'-e','FIXTURE_INITIAL_STATE=/initial-state.json',
                    '-v',str(saved)+':/initial-state.json:ro','-v',str(self.material)+':/fixture:ro','--memory','192m','--cpus','1','--pids-limit','64',
                    '--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--cap-drop','ALL','--security-opt','no-new-privileges',self.args.refresh_authority_image).stdout.strip()
                self.connect_saved_networks(replacement,old['NetworkSettings']['Networks'])
                self.docker('start',replacement)
                def ready():
                    try:
                        stats=self.authority(group,'/stats')
                        return 'request_totals' in stats['state'] and 'activation_epochs' in stats['state'] and authority_now(stats)>=clock
                    except OSError:return False
                if not self.until(ready):raise RuntimeError('replacement test authority did not become healthy')
            except Exception:
                # Keep the original ID/configuration available until verified
                # replacement; never rebuild a rollback container from secrets.
                if replacement:
                    self.docker('stop',replacement);self.docker('rm',replacement)
                current=json.loads(self.docker('inspect',old['Id']).stdout)[0]
                if current['Name'].lstrip('/')!=server['name']:self.docker('rename',old['Id'],server['name'])
                self.connect_saved_networks(old['Id'],old['NetworkSettings']['Networks'])
                self.docker('start',old['Id'])
                raise
            self.docker('rm',old['Id'])
            self.record('test_authority_refreshed_without_clock_rollback:'+group,True)

    def persist_authority_state(self,group):
        name=self.authorities[group]['name']
        if name!=self.run_id+'-'+group+'-authority' or not self.require_owned('container',name):
            raise RuntimeError('refuse persistence for an unexpected authority')
        info=json.loads(self.docker('inspect',name).stdout)[0]
        mounts=[r for r in info.get('Mounts',[]) if r.get('Destination')=='/initial-state.json' and r.get('Type')=='bind']
        if len(mounts)!=1:raise RuntimeError('authority has no unique persisted state mount')
        saved=Path(mounts[0]['Source']).resolve()
        if not saved.is_relative_to(self.fixture.parent) or saved.name!='authority-initial-'+group+'.json':
            raise RuntimeError('authority state mount is outside private fixture state')
        # Write the existing bind-mounted inode; replacing the file would leave
        # the running container attached to an older inode.
        self.private(saved,json.dumps(self.authority(group,'/stats')['state']))

    def cache_state(self,p):
        out={}
        for node in p['nodes']:
            path=Path(self.nodes[node]['data'])/'license_cache.json'
            try:out[node]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'mtime_ns':path.stat().st_mtime_ns}
            except FileNotFoundError:out[node]=None
        return out

    def state_matches(self,p,active):
        for node in p['nodes']:
            health=self.api(node,'/health')[1].get('license',{})
            if health.get('status')!=('active' if active else 'unlicensed'):return False
        return all(self.api(node,'/api/v1/queries/active')[0]==(200 if active else 403) for node in p['nodes'])

    def await_state(self,p,active,reason=None,activation=False):
        self.current=p['id'];started=time.monotonic()
        def delivered():
            seen={e['fingerprint'] for e in self.events(p) if (e.get('successful_verdict') if active else e.get('rejection_reason')==reason) and
                  (not activation or e.get('activate') and e.get('activation_epoch_consumed'))}
            return set(p['fingerprints']).issubset(seen) and self.state_matches(p,active)
        ok=self.until(delivered,timeout=25)
        self.record('active' if active else 'definitive_suspension',ok,{'seconds':round(time.monotonic()-started,3),'reason':reason,'participants':len(p['nodes'])})
        caches=self.cache_state(p)
        if active:self.record('fresh_verified_cache_saved',self.until(lambda:all(v and v['mtime_ns']>=self.phase_started_ns for v in self.cache_state(p).values())))
        else:self.record('rejected_caches_removed',self.until(lambda:all(v is None for v in self.cache_state(p).values())),caches)
        return ok

    def preserve(self,p):
        self.current=p['id']
        def exact_ids():
            code,body=self.api(p['leader'],'/api/v1/query',{'sql':'SELECT record_id FROM events'})
            ids=[r[0] for r in body.get('data',[])] if code==200 and body.get('columns')==['record_id'] else []
            return len(ids)==len(set(ids))==len(self.expected_ids[p['id']]) and set(ids)==self.expected_ids[p['id']]
        self.record('acknowledged_ids_present_once',self.until(exact_ids),{'expected':len(self.expected_ids[p['id']])})
        cold=self.query_count(p['leader'],'synthetic_cold')
        self.record('cold_rows_preserved',cold[0]==200 and cold[1].get('columns')==['n'] and self.count(cold[1])==30,cold)
        saved=json.loads((self.fixture/p['id']/'rbac.private.json').read_text());token=self.secret(saved['token'])
        allow=self.query_count(p['leader']);denied=self.api(p['leader'],'/api/v1/query',{'sql':'SELECT count(*) AS n FROM private_events'},token=token)
        scoped=self.api(p['leader'],'/api/v1/query',{'sql':'SELECT count(*) AS n FROM events'},token=token)
        self.record('existing_rbac_grant_and_denial_preserved',scoped[0]==200 and denied[0]==403,{'allowed':scoped[0],'denied':denied[0]})
        for node in p['nodes']:
            snap=self.storage_snapshot(node);before=self.baselines.get(node)
            self.record('sqlite_integrity:'+self.nodes[node]['role'],snap['integrity']=='ok')
            if before:
                retained=all(set(v['row_hashes']).issubset(set(snap['config'].get(k,{}).get('row_hashes',[]))) for k,v in before['config'].items())
                history=all(set(v).issubset(set(snap['histories'].get(k,[]))) for k,v in before['histories'].items())
                self.record('configuration_rows_retained:'+self.nodes[node]['role'],retained)
                self.record('completed_history_retained:'+self.nodes[node]['role'],history)
        return allow

    def probe_services(self,p,active,mutate=True):
        self.current=p['id'];node=p['leader'];observed={}
        for name,path in [('rbac','/api/v1/rbac/organizations'),('audit','/api/v1/audit/logs?limit=2'),('tiering','/api/v1/tiering/status'),
                          ('governance','/api/v1/governance/policies'),('query_management','/api/v1/queries/history')]:
            observed[name]=self.api(node,path)
            self.record(name+'_feature',observed[name][0]==(200 if active else 403),observed[name])
        if mutate:
            mutation=self.api(node,'/api/v1/rbac/organizations',{'name':'normalization-'+secrets.token_hex(6)})
            self.record('management_writable' if active else 'management_refused',mutation[0]==(201 if active else 403),mutation)
        saved=json.loads((self.fixture/p['id']/'rbac.private.json').read_text())
        governed=self.api(node,'/api/v1/query',{'sql':'SELECT record_id,value FROM events ORDER BY value LIMIT 10'},token=self.secret(saved['token']))
        self.record('governance_reenabled' if active else 'governance_dormant',governed[0]==200 and governed[1].get('row_count')==(1 if active else 10),governed)
        migrate=self.api(node,'/api/v1/tiering/migrate',{'database':'license_test','measurement':'normalization_none'})
        self.record('migration_admission_restored' if active else 'migration_refused',migrate[0]==(200 if active else 403),migrate)
        self.write_probe(p,self.phase_name);self.preserve(p)
        cluster=self.api(node,'/api/v1/cluster')
        observed['cluster']=cluster
        if active:
            self.record('cluster_membership_retained',cluster[0]==200 and cluster[1].get('node_count')==len(p['nodes']))
            logs=self.docker('logs',node)
            failover=failover_configuration(logs.stdout+logs.stderr)
            self.record('startup_failover_configuration_matches_entitlement',None if failover is None else failover==('writer_failover' in p['features']),failover,
                note='Retained processes have failover enabled in their configuration. This checks the startup permission only; actual replacement during suspension/recovery is untested.')
        self.private(self.state/('services-'+self.phase_name+'-'+p['id']+'.json'),json.dumps(self.redact(observed),indent=2))

    def assert_peers(self,target):
        for p in self.profiles:
            if p['id']!=target['id']:
                self.current=p['id'];self.record('other_license_unaffected',self.state_matches(p,True))

    def reason_logged(self,p,reason):
        since=dt.datetime.fromtimestamp(self.phase_started_ns/1e9,UTC).isoformat()
        evidence={}
        for node in p['nodes']:
            logs=self.docker('logs','--since',since,node)
            selected=[line for line in (logs.stdout+logs.stderr).splitlines() if reason in line]
            evidence[self.nodes[node]['role']]=self.redact(selected[-3:])
        self.record('rejection_reason_logged_on_each_node',all(evidence.values()),evidence)

    def sampled_continuity(self,p,seconds=5):
        baseline=self.cache_state(p);samples=[];deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            cache=self.cache_state(p)
            intact=all(cache[n] and baseline[n] and cache[n]['sha256']==baseline[n]['sha256'] for n in p['nodes'])
            samples.append(intact and self.state_matches(p,True));time.sleep(.4)
        self.record('sampled_active_and_cache_continuity',all(samples) and bool(samples),{'samples':len(samples),'seconds':seconds})

    def activation_recovery(self,p,reason,activation_mode='valid'):
        epoch=p['reactivation_epoch']+1
        self.set_phase(p['id']+'-'+reason+'-'+activation_mode,{p['id']:{'mode':'valid','activation_mode':activation_mode,'reactivation_epoch':epoch,'reactivation_reason':reason}})
        self.current=p['id']
        if activation_mode=='503':
            self.sampled_continuity(p)
            seen={e['fingerprint'] for e in self.events(p) if e.get('activate') and e.get('mode')=='503'}
            self.record('activation_outage_exercised_each_node',set(p['fingerprints']).issubset(seen))
            self.assert_peers(p)
            self.set_phase(p['id']+'-activation-outage-recovered',{p['id']:{'activation_mode':'valid'}})
        elif activation_mode=='suspended':
            self.await_state(p,False,'license is suspended');self.reason_logged(p,'license is suspended')
            self.probe_services(p,False);self.assert_peers(p)
            self.set_phase(p['id']+'-activation-refusal-recovered',{p['id']:{'activation_mode':'valid'}})
        self.await_state(p,True,activation=True)
        # A later normal verify must not repeatedly try activation.
        before={e['fingerprint'] for e in self.events(p) if e.get('activate') and e.get('activation_epoch_consumed')}
        counters=self.request_totals(p)
        self.sampled_continuity(p,4)
        events=self.events(p)
        plain={e['fingerprint'] for e in events if not e.get('activate') and e.get('mode')=='valid' and e.get('successful_verdict')}
        self.current=p['id'];self.record('reactivation_returns_to_plain_verify',set(p['fingerprints']).issubset(before) and set(p['fingerprints']).issubset(plain))
        after=self.request_totals(p)
        self.record('no_reactivation_loop',all(after[f]['activate']==counters[f]['activate'] and after[f]['verify']>counters[f]['verify'] for f in p['fingerprints']))
        self.probe_services(p,True)

    def drain_jobs(self):
        def drained():
            for row in self.nodes.values():
                with sqlite3.connect('file:'+row['data']+'/arc.db?mode=ro',uri=True) as db:
                    if db.execute("SELECT COUNT(*) FROM continuous_query_executions WHERE status IN ('running','pending','started')").fetchone()[0]:return False
                    if db.execute("SELECT COUNT(*) FROM retention_executions WHERE status IN ('running','pending','started')").fetchone()[0]:return False
                    if db.execute('SELECT COUNT(*) FROM tier_migrations WHERE completed_at IS NULL AND error IS NULL').fetchone()[0]:return False
            return True
        stable=0;deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            stable=stable+1 if drained() else 0
            if stable>=3:return True
            time.sleep(1)
        return False

    def feed_retention(self,p):
        identity=secrets.token_hex(8);stamp=time.time_ns();p['pending_retention_id']=identity
        response=self.api(p['leader'],'/api/v1/write/line-protocol',
            f'retention_probe,age=old,record_id={identity} value=1i {stamp-3*24*3600*10**9}\nretention_probe,age=current,record_id={identity} value=1i {stamp}\n')
        self.record('pending_retention_data_acked',response[0]==204,response)

    def scheduled_rows(self,p):
        with sqlite3.connect('file:'+self.nodes[p['leader']]['data']+'/arc.db?mode=ro',uri=True) as db:
            db.execute('BEGIN')
            rows={name:{r[0] for r in db.execute('SELECT id FROM '+name)} for name in
                  ('continuous_query_executions','retention_executions','tier_migrations')}
            db.rollback()
        return rows

    def observe_suspended_background(self):
        before={p['id']:self.scheduled_rows(p) for p in self.profiles}
        deadline=time.monotonic()+65
        while time.monotonic()<deadline:
            if self.watch_failures:raise RuntimeError('protected process changed')
            time.sleep(1)
        for p in self.profiles:
            self.current=p['id'];after=self.scheduled_rows(p)
            self.record('no_new_licensed_jobs_while_suspended',all(after[k]==v for k,v in before[p['id']].items()),
                {'before':{k:len(v) for k,v in before[p['id']].items()},'after':{k:len(v) for k,v in after.items()}},
                note='Measured after accepted work drains; system/audit logging is not conflated with scheduled licensed work.')

    def retention_rows(self,p):
        code,body=self.api(p['leader'],'/api/v1/query',{'sql':"SELECT age,count(*) AS n FROM retention_probe WHERE record_id='"+p['pending_retention_id']+"' GROUP BY age ORDER BY age"})
        return {r[0]:r[1] for r in body.get('data',[])} if code==200 and body.get('columns')==['age','n'] else None

    def candidate_rows(self,p):
        with sqlite3.connect('file:'+self.nodes[p['leader']]['data']+'/arc.db?mode=ro',uri=True) as db:
            return db.execute('SELECT path,tier,partition_time,quarantined_at FROM tier_files WHERE measurement=?',(p['candidate'],)).fetchall()

    def seed_candidate(self,p):
        self.current=p['id'];measurement='normalization_migration_'+self.case_id;p['candidate']=measurement
        stamp=time.time_ns()-3*24*3600*10**9
        for first in (0,15):
            response=self.api(p['leader'],'/api/v1/write/line-protocol',''.join(f'{measurement},record_id=n{i} value={i}i {stamp+i}\n' for i in range(first,first+15)))
            self.record('migration_probe_acked',response[0]==204,response);time.sleep(1)
        cluster=self.api(p['leader'],'/api/v1/cluster')[1];holder=cluster.get('active_compactor',{}).get('node_id')
        if not holder:holder=next((r['id'] for r in cluster.get('nodes',[]) if r.get('role')=='compactor'),None)
        compactor=next((n for n in p['nodes'] if self.nodes[n]['hostname']==holder),None)
        if not compactor:self.record('candidate_compactor_available',False);return
        self.until(lambda:self.query_count(compactor,measurement)[1].get('columns')==['n'])
        response=self.api(compactor,'/api/v1/compaction/trigger?tier=daily&database=license_test&measurement='+measurement,{})
        self.record('candidate_compaction_requested',response[0] in (200,202),response)
        if response[0] not in (200,202):return
        cycle=response[1].get('cycle_id')
        self.record('candidate_compaction_completed',self.until(lambda:self.api(compactor,'/api/v1/compaction/cycles/'+str(cycle))[1].get('status')=='completed',timeout=60))
        def eligible():
            rows=self.candidate_rows(p)
            return any(tier=='hot' and path.endswith('_daily.parquet') and not quarantine and
                dt.datetime.fromisoformat(str(partition)).date()<=dt.datetime.now(UTC).date()-dt.timedelta(days=1) and
                (Path(self.nodes[p['leader']]['data'])/'storage'/path).exists() for path,tier,partition,quarantine in rows)
        file_ready=self.until(eligible,timeout=20)
        self.api(p['leader'],'/api/v1/tiering/scan',{})
        preview=self.api(p['leader'],'/api/v1/tiering/migrate',{'database':'license_test','measurement':measurement,'dry_run':True})
        p['candidate_ready']=file_ready and preview[0]==200 and preview[1].get('would_migrate',0)>0
        self.record('real_daily_hot_candidate_eligible',True if p['candidate_ready'] else None,{'files':self.candidate_rows(p),'preview':preview},
            note='Prepared while licensed, before suspension. Missing eligibility is an INCONCLUSIVE fixture gap, never a product failure or vacuous pass.')

    def prepare_and_suspend(self):
        for p in self.profiles:
            # Leave nearly a full cron minute to prepare an eligible file before
            # suspending; do not change either the host or container clock.
            delay=(62-time.time()%60)%60
            until=time.monotonic()+delay
            while time.monotonic()<until:
                if self.watch_failures:raise RuntimeError('protected process changed')
                time.sleep(min(1,until-time.monotonic()))
            self.seed_candidate(p)
            self.set_phase('candidate-suspended-'+p['id'],{p['id']:{'mode':'suspended','activation_mode':'suspended'}})
            self.await_state(p,False,'license is suspended')
        self.set_phase('all-suspended')

    def focused_recheck(self):
        self.prepare_and_suspend()
        self.record('accepted_background_work_drained',self.drain_jobs())
        self.observe_suspended_background()
        for p in self.profiles:
            self.current=p['id'];rows=self.candidate_rows(p)
            self.record('eligible_migration_blocked_during_suspension',
                bool(rows) and all(r[1]=='hot' for r in rows) if p.get('candidate_ready') else None,rows,
                note='INCONCLUSIVE unless licensed dry-run and physical daily file established eligibility before suspension.')
        self.set_phase('focused-reactivated',{p['id']:{'mode':'valid','activation_mode':'valid'} for p in self.profiles})
        for p in self.profiles:self.await_state(p,True)
        deadline=time.monotonic()+85
        while time.monotonic()<deadline:
            if self.watch_failures:raise RuntimeError('protected process changed')
            time.sleep(1)
        for p in self.profiles:
            self.current=p['id'];rows=self.candidate_rows(p)
            self.record('eligible_automatic_migration_resumed',any(r[1]=='cold' for r in rows) if p.get('candidate_ready') else None,rows)
            count=self.query_count(p['leader'],p['candidate'])
            self.record('migrated_data_count_exact',count[0]==200 and count[1].get('columns')==['n'] and self.count(count[1])==30,count)
            self.probe_services(p,True,mutate=False)

    def auth_mutation_while_suspended(self,p):
        self.current=p['id'];response=self.api(p['leader'],'/api/v1/auth/tokens',{'name':'normalization-oss-'+self.case_id,'permissions':['read']})
        token=response[1].get('token') if response[0]==201 else None
        if token:self.secret(token)
        self.record('oss_token_created_while_suspended',response[0]==201,self.redact(response))
        if not token:return
        verified=self.api(p['leader'],'/api/v1/auth/verify',token=token)
        token_id=verified[1].get('token_info',{}).get('id')
        rotated=self.api(p['leader'],f'/api/v1/auth/tokens/{token_id}/rotate',{})
        new=rotated[1].get('new_token') if rotated[0]==200 else None
        if new:self.secret(new)
        self.record('oss_token_rotated_while_suspended',bool(new),self.redact(rotated))
        if new:self.oss_tokens[p['id']]={'old':token,'new':new,'id':token_id}
        self.private(self.state/'oss-tokens.private.json',json.dumps(self.oss_tokens,indent=2))

    def audit_ids(self,p):
        out={}
        for node in p['nodes']:
            with sqlite3.connect('file:'+self.nodes[node]['data']+'/arc.db?mode=ro',uri=True) as db:
                out[node]={r[0] for r in db.execute("SELECT id FROM audit_logs WHERE event_type IN ('data.query','data.write')")}
        return out

    def await_normal_background(self):
        before={}
        for p in self.profiles:
            cq=self.api(p['leader'],f"/api/v1/continuous_queries/{p['cq_id']}/executions?limit=100")
            ret=self.api(p['leader'],f"/api/v1/retention/{p['retention_id']}/executions?limit=100")
            before[p['id']]={'cq':{r.get('execution_id') for r in cq[1].get('executions',[])},'ret':{r.get('id') for r in ret[1].get('executions',[])},'audit':self.audit_ids(p)}
            self.write_probe(p,'normalization-background')
        deadline=time.monotonic()+85
        while time.monotonic()<deadline:
            if self.watch_failures:raise RuntimeError('protected process changed')
            time.sleep(1)
        for p in self.profiles:
            self.current=p['id'];cq=self.api(p['leader'],f"/api/v1/continuous_queries/{p['cq_id']}/executions?limit=100")
            ret=self.api(p['leader'],f"/api/v1/retention/{p['retention_id']}/executions?limit=100")
            self.record('new_scheduled_cq_output_after_reactivation',any(r.get('execution_id') not in before[p['id']]['cq'] and
                str(r.get('execution_id','')).startswith('cq-sched-') and r.get('status')=='completed' and r.get('records_written',0)>0 for r in cq[1].get('executions',[])),cq)
            self.record('new_retention_execution_after_reactivation',any(r.get('id') not in before[p['id']]['ret'] and r.get('status')=='completed' for r in ret[1].get('executions',[])),ret)
            self.record('retention_resumed_with_correct_data_effects',self.retention_rows(p)=={'current':1},self.retention_rows(p))
            self.record('new_audit_data_events_after_reactivation',any(self.audit_ids(p)[n]-before[p['id']]['audit'][n] for n in p['nodes']))
            rows=self.candidate_rows(p)
            self.record('automatic_tier_migration_resumed',any(r[1]=='cold' for r in rows) if p.get('candidate_ready') else None,rows)
            count=self.query_count(p['leader'],p['candidate']);self.record('migrated_data_count_exact',count[0]==200 and count[1].get('columns')==['n'] and self.count(count[1])==30,count)
            self.preserve(p)
            token=self.oss_tokens.get(p['id'])
            if token:
                old=self.api(p['leader'],'/api/v1/auth/verify',token=token['old']);new=self.api(p['leader'],'/api/v1/auth/verify',token=token['new'])
                self.record('offline_period_token_rotation_retained',old[0]==401 and new[0]==200,{'old_status':old[0],'new_status':new[0]},
                    note='Auth changes occurred while unlicensed in the retained cluster; this does not prove inverse OSS/FSM reconciliation.')

    def startup_probe(self):
        p=self.profiles[0];name=self.run_id+'-normalization-startup-'+self.case_id;hostname='normalization-'+self.case_id
        folder=self.state/'startup-probe';data=folder/'data';data.mkdir(mode=0o700,parents=True)
        token=self.secret(secrets.token_hex(32));env=self.base_env(p['_key'],token,self.secret(secrets.token_hex(32)),hostname)
        env.update(SSL_CERT_FILE='/run/fixture-ca.crt',ARC_CLUSTER_SEEDS='',ARC_CLUSTER_NODE_ID=hostname,ARC_CLUSTER_ROLE='writer',
            ARC_CLUSTER_RAFT_BOOTSTRAP='true',ARC_CLUSTER_ADVERTISE_ADDR=hostname+':9100',ARC_CLUSTER_RAFT_ADVERTISE_ADDR=hostname+':9200',ARC_CLUSTER_API_ADDR=hostname+':8000',
            ARC_CLUSTER_REPLICATION_ENABLED='false',ARC_CLUSTER_FAILOVER_ENABLED='false',ARC_CLUSTER_SHARED_STORAGE_MODE='false',
            ARC_DATABASE_THREAD_COUNT='2',ARC_DATABASE_MEMORY_LIMIT='64MB',ARC_COMPACTION_ENABLED='false',ARC_TIERED_STORAGE_ENABLED='false',
            ARC_CONTINUOUS_QUERY_ENABLED='false',ARC_RETENTION_ENABLED='false',ARC_AUDIT_LOG_ENABLED='false',ARC_GOVERNANCE_ENABLED='false')
        self.private(folder/'probe.env',''.join(f'{k}={v}\n' for k,v in env.items()))
        self.docker('run','-d','--name',name,'--hostname',hostname,'--label',self.label,'--network',self.run_id+'-license0','--network-alias',hostname,
            '--memory','512m','--cpus','.5','--pids-limit','512','--env-file',folder/'probe.env','-v',str(data)+':/app/data',
            '-v',str(self.material/'tls.crt')+':/run/fixture-ca.crt:ro',self.args.image)
        info=json.loads(self.docker('inspect',name).stdout)[0];self.probe_id=info['Id'];self.probe=name
        url='http://'+info['NetworkSettings']['Networks'][self.run_id+'-license0']['IPAddress']+':8000'
        self.nodes[name]={'url':url,'token':token,'data':str(data),'install':'startup-probe','role':'probe','hostname':hostname,'image_id':info['Image']}
        self.wait(name);self.record('suspended_boot_standalone',not self.api(name,'/api/v1/cluster')[1].get('enabled',True),self.api(name,'/health'))
        unknown={e['fingerprint'] for e in self.events(p) if e.get('rejection_reason')=='license is suspended' and e['fingerprint'] not in p['fingerprints']}
        if len(unknown)!=1:raise RuntimeError('could not identify exactly one disposable probe fingerprint')
        self.probe_fp=next(iter(unknown))
        response=self.api(name,'/api/v1/write/line-protocol',''.join(f'startup_events,record_id=s{i} value={i}i {time.time_ns()+i}\n' for i in range(5)))
        self.record('startup_probe_rows_acked',response[0]==204,response)
        self.record('startup_probe_rows_readable',self.until(self.startup_rows_exact))

    def startup_rows_exact(self):
        code,body=self.api(self.probe,'/api/v1/query',{'sql':'SELECT record_id FROM startup_events'})
        rows=[r[0] for r in body.get('data',[])] if code==200 and body.get('columns')==['record_id'] else []
        return len(rows)==5 and set(rows)=={'s'+str(i) for i in range(5)}

    def check_startup_normalization(self):
        if not self.probe:return
        name=self.probe;self.current='startup-probe'
        before=self.request_totals(self.profiles[0],self.probe_fp)
        recovered=self.until(lambda:self.api(name,'/api/v1/queries/active')[0]==200,timeout=12)
        after=self.request_totals(self.profiles[0],self.probe_fp)
        self.record('automatic_normalization_after_suspended_boot',recovered,self.api(name,'/health'),
            note='A discarded boot-time license client cannot observe server reactivation; existing licensed-process recovery does not cover this case.')
        self.record('startup_probe_periodic_verification_observed',after['verify']>before['verify'],{'before':before,'after':after})
        if not recovered:
            before=json.loads(self.docker('inspect',name).stdout)[0]
            if before['Id']!=self.probe_id:raise RuntimeError('disposable probe identity changed')
            self.docker('restart','-t','30',name);self.wait(name,timeout=60)
            self.record('disposable_restart_restores_license_features',self.api(name,'/api/v1/queries/active')[0]==200,self.api(name,'/health'))
            self.record('disposable_restart_preserves_oss_rows',self.startup_rows_exact(),self.query_count(name,'startup_events'))

    def run(self):
        watcher=threading.Thread(target=self.watch_originals,daemon=True);watcher.start()
        try:
            if self.args.refresh_authority_image:self.refresh_authorities()
            future=max(authority_now(self.authority(g,'/stats')).date() for g in ('paid','trial'))+dt.timedelta(days=30)
            for p in self.profiles:p['term_ends_at']=p['expires_at']=future.isoformat()+'T12:00:00Z'
            self.set_phase('active-baseline',anchor=future.isoformat()+'T00:00:00Z')
            for p in self.profiles:
                self.await_state(p,True)
                for node in p['nodes']:self.baselines[node]=self.storage_snapshot(node)
                self.probe_services(p,True)
                if not self.args.focused:self.exercise_jobs(p,False)
            if self.args.focused:
                self.focused_recheck();return
            for p in self.profiles:
                requests_before=self.request_totals(p)
                self.set_phase('suspend-'+p['id'],{p['id']:{'mode':'suspended','activation_mode':'suspended'}})
                self.await_state(p,False,'license is suspended');self.reason_logged(p,'license is suspended')
                self.probe_services(p,False);self.assert_peers(p)
                requests_after=self.request_totals(p)
                self.current=p['id'];self.record('suspension_does_not_attempt_reactivation',all(requests_after[f]['activate']==requests_before[f]['activate'] for f in p['fingerprints']))
                self.set_phase('reactivate-'+p['id'],{p['id']:{'mode':'valid','activation_mode':'valid'}})
                self.await_state(p,True);self.probe_services(p,True)
            for p in self.profiles:
                self.activation_recovery(p,'missing_activation')
                self.activation_recovery(p,'revoked_activation')
                self.activation_recovery(p,'missing_activation','503')
                self.activation_recovery(p,'revoked_activation','suspended')
            self.prepare_and_suspend()
            for p in self.profiles:self.await_state(p,False,'license is suspended')
            self.record('accepted_background_work_drained',self.drain_jobs())
            self.startup_probe()
            for p in self.profiles:
                self.current=p['id'];self.feed_retention(p);self.auth_mutation_while_suspended(p)
            self.observe_suspended_background()
            for p in self.profiles:
                self.current=p['id'];self.record('retention_did_not_run_while_suspended',self.retention_rows(p)=={'old':1,'current':1},self.retention_rows(p))
                self.record('migration_did_not_run_while_suspended',bool(self.candidate_rows(p)) and all(r[1]=='hot' for r in self.candidate_rows(p)) if p.get('candidate_ready') else None,self.candidate_rows(p))
            self.set_phase('all-reactivated',{p['id']:{'mode':'valid','activation_mode':'valid'} for p in self.profiles})
            for p in self.profiles:self.await_state(p,True);self.probe_services(p,True)
            self.check_startup_normalization();self.await_normal_background()
            self.record('full_inverse_handoff_not_established',observed='Forward OSS ownership/fencing is unimplemented; these existing clustered processes cannot establish safe inverse handoff normalization.')
        except Exception as error:
            self.record('harness_exception',False,str(error));raise
        finally:
            # Best-effort restore valid authority status; never report full
            # normalization merely because this cleanup command succeeded.
            for p in self.profiles:p['mode']=p['activation_mode']='valid'
            for g in ('paid','trial'):
                try:
                    self.control(g,profiles=self.authority_profiles(g),mode='valid',activation_mode='valid')
                    self.persist_authority_state(g)
                except Exception as error:self.record('active_authority_restore_failed',False,str(error))
            if self.probe:
                info=json.loads(self.docker('inspect',self.probe).stdout)[0]
                if info['Id']!=self.probe_id:raise RuntimeError('refuse cleanup of changed disposable probe')
                logs=self.docker('logs',self.probe);self.private(self.state/'startup-probe.redacted.log',self.redact(logs.stdout+logs.stderr))
                self.docker('stop','-t','30',self.probe);self.docker('rm',self.probe)
                self.nodes.pop(self.probe,None)
            self.watch_stop.set();watcher.join(timeout=10)
            after=self.protected_snapshot();self.record('all_original_and_retained_arc_processes_unchanged',not self.watch_failures and after==self.protected_before,{'samples':self.watch_samples})
            self.private(self.state/'protected-after.json',json.dumps(after,indent=2))
            self.private(self.state/'protection.json',json.dumps({'samples':self.watch_samples,'failures':self.watch_failures,'unchanged':after==self.protected_before},indent=2))
            for p in self.profiles:self.collect(p['id'])
            for g in ('paid','trial'):self.private(self.state/('authority-'+g+'-events.private.json'),json.dumps(self.authority(g,'/stats'),indent=2))
            self.write_report()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',required=True);p.add_argument('--fixture-state',required=True);p.add_argument('--material',required=True);p.add_argument('--live-state',required=True)
    p.add_argument('--run-id',default='arc-license-matrix');p.add_argument('--image',default='arc-license-matrix:fast')
    p.add_argument('--focused',action='store_true',help='recheck only corrected failover and eligible migration oracles')
    p.add_argument('--refresh-authority-image',help='replace only the two owned test authorities, preserving their clock state and IPs')
    args=p.parse_args();suite=Normalization(args);suite.run()
    raise SystemExit(any(r['result']=='FAIL' for r in suite.results))


if __name__=='__main__':main()
