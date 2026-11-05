#!/usr/bin/env python3
"""Production lifecycle acceptance in NEW isolated stacks; never resumes old stacks."""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import socket
import secrets
import sqlite3
import threading
import time

from three_stacks import Matrix, UTC


class Lifecycle(Matrix):
    def base_env(self,key,admin,shared,cluster_name):
        env=super().base_env(key,admin,shared,cluster_name)
        if getattr(self.args,'shared_unlimited',False) and cluster_name=='license0':
            env.update(ARC_CLUSTER_SHARED_STORAGE_MODE='true',ARC_STORAGE_BACKEND='s3',ARC_STORAGE_S3_BUCKET='license0-hot',
                       ARC_STORAGE_S3_REGION='us-east-1',ARC_STORAGE_S3_ENDPOINT='http://cold-store:8333',ARC_STORAGE_S3_ACCESS_KEY='local-test',
                       ARC_STORAGE_S3_SECRET_KEY='local-test',ARC_STORAGE_S3_USE_SSL='false',ARC_STORAGE_S3_PATH_STYLE='true')
        if getattr(self.args,'iceberg',False) and cluster_name in ('license0','license1','license2'):
            env.update(ARC_ICEBERG_ENABLED='true',ARC_ICEBERG_RECONCILE_INTERVAL='1')
            if cluster_name=='license0':env.update(ARC_ICEBERG_WAREHOUSE='s3://license0-hot/exports',ARC_ICEBERG_CATALOG_DB_PATH='/app/data/iceberg-original.db')
            if cluster_name=='license2':env.update(ARC_ICEBERG_WAREHOUSE='/app/data/storage/custom-export',ARC_ICEBERG_CATALOG_DB_PATH='/app/data/iceberg-original.db')
        return env

    def iceberg_exact(self,node,location,expected):
        result=self.docker('exec',node,'/app/iceberg-audit',location,'http://cold-store:8333',check=False,timeout=45)
        if result.returncode!=0:return False
        try:ids=json.loads(result.stdout)['ids']
        except (ValueError,KeyError):return False
        return len(ids)==len(set(ids))==len(expected) and set(ids)==set(expected)

    def retained_iceberg_catalogs(self,p):
        result={}
        for n in p['nodes']:
            path=Path(self.nodes[n]['data'])/('arc.db' if p['id']=='license1' else 'iceberg-original.db')
            with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True) as db:
                result[n]=db.execute('SELECT table_namespace,table_name,metadata_location FROM iceberg_tables ORDER BY table_namespace,table_name').fetchall()
        return result

    def start_node(self,install,role,env,image=None,extra=(),cluster_role=None):
        node=super().start_node(install,role,env,image,extra,cluster_role,node_id='' if getattr(self.args,'auto_node_ids',False) else None)
        self.nodes[node]['node_id']=self.nodes[node]['hostname']+('-1' if getattr(self.args,'auto_node_ids',False) else '')
        return node

    def api(self,node,path,payload=None,method=None,token=True,timeout=30):
        result=super().api(node,path,payload,method,token,timeout)
        if self.phase_name=='setup' and path=='/api/v1/retention/' and payload and result[0]==503 and 'being adopted' in str(result[1]):
            self.record('retention_setup_waits_for_adoption',observed={'http':503,'reason':'cluster policy adoption in progress'})
            deadline=time.monotonic()+15
            while result[0]==503 and 'being adopted' in str(result[1]) and time.monotonic()<deadline:
                time.sleep(.3);result=super().api(node,path,payload,method,token,timeout)
        return result

    def profiles_from_verified_cache(self):
        source=json.loads(Path(self.args.verified_profiles).read_text())
        for p in source:
            p={k:p[k] for k in ('id','profile_id','tier','features','max_cores','max_machines','license_kind','source_payload_sha256')}
            p.update(term_ends_at=self.args.term_date+'T12:00:00Z',expires_at=self.args.term_date+'T12:00:00Z',issued_at='2025-12-18T12:00:00Z',enforce_expiry=True)
            p['synthetic_key']=self.secret('LOCAL-FIXTURE-LIFECYCLE-'+p['id'].upper());self.profiles.append(p)
        self.installations=[{k:v for k,v in p.items() if k!='synthetic_key'} for p in self.profiles]
        self.private(self.state/'profiles.json',json.dumps(self.installations,indent=2))

    def snapshots(self):
        result=self.docker('ps','-a','--filter','label=arc-license-tests=arc-license-matrix','--format','{{.Names}}')
        names=result.stdout.splitlines()
        rows=json.loads(self.docker('inspect',*names).stdout)
        return {r['Name']:{'id':r['Id'],'image':r['Image'],'started':r['State']['StartedAt'],'restarts':r['RestartCount'],'running':r['State']['Running']} for r in rows}

    def active(self,p):
        return all(self.api(n,'/health')[1].get('license',{}).get('status') in ('active','grace_period') for n in p['nodes'])

    def exact(self,p):
        code,body=self.api(p['leader'],'/api/v1/query',{'sql':'SELECT record_id FROM events'})
        ids=[r[0] for r in body.get('data',[])] if code==200 and body.get('columns')==['record_id'] else []
        return len(ids)==len(set(ids))==len(self.expected_ids[p['id']]) and set(ids)==self.expected_ids[p['id']]

    def reduced(self,p):
        owners={}
        for n in p['nodes']:
            code,body=self.api(n,'/api/v1/cluster')
            if code!=200:return False
            state=body.get('license_lifecycle',{})
            if state.get('mode')!='reduced':return False
            if owners and owners!=state.get('roles'):return False
            owners=state.get('roles')
            selected=owners.get(self.nodes[n]['cluster_role'])==self.nodes[n]['node_id']
            if self.api(n,'/ready')[0]!=(200 if selected else 503):return False
            if selected and self.nodes[n]['cluster_role'] in ('writer','standalone') and self.api(n,'/ready/write')[0]!=200:return False
            query=self.query_count(n)[0]
            if not selected and query!=503:return False
        if owners:
            writer=owners.get('writer',owners.get('standalone'))
            p['leader']=next(n for n in p['nodes'] if self.nodes[n]['node_id']==writer)
        return bool(owners)

    def final_owner(self,p):
        live=[]
        for n in p['nodes']:
            code,body=self.api(n,'/health',timeout=2)
            if code==200:
                cluster=self.api(n,'/api/v1/cluster',timeout=2)
                if cluster[0]!=200 or cluster[1].get('enabled',True):return None
                if self.api(n,'/ready/write',timeout=2)[0]!=200:return None
                live.append(n)
            else:
                if self.api(n,'/api/v1/query',{'sql':'SELECT 1'},timeout=2)[0]==200:return None
            # Probe the actual Raft transport; a desired policy flag is not proof.
            host=self.nodes[n]['url'].split('//')[1].split(':')[0]
            try:
                with socket.create_connection((host,9200),timeout=.2):return None
            except OSError:pass
        return live[0] if len(live)==1 else None

    def check_final(self,p,label):
        self.current=p['id'];owner=None
        def transitioned():
            nonlocal owner
            owner=self.final_owner(p)
            return bool(owner)
        ok=self.until(transitioned,timeout=150)
        self.record(label+':single_oss_owner_raft_closed_peers_fenced',ok,owner)
        if not ok:
            self.collect(p['id']);return False
        previous=p['leader'];p['leader']=owner
        p.setdefault('sealed_ids',set(self.expected_ids[p['id']]))
        p.setdefault('oss_ids',{})
        if owner!=previous:
            self.record(label+':owner_changed_with_retained_expired_configuration',observed={'previous':previous,'current':owner},note='Each node retains its local OSS changes; this restart policy does not promise migration of OSS-period writes to another node.')
        self.expected_ids[p['id']]=set(p['sealed_ids'])|set(p['oss_ids'].get(owner,[]))
        self.record(label+':selected_namespace_ids_exact' ,self.until(lambda:self.exact(p)))
        cold=self.query_count(owner,'synthetic_cold')
        self.record(label+':cold_rows_exact',cold[0]==200 and cold[1].get('columns')==['n'] and self.count(cold[1])==30,cold)
        before=set(self.expected_ids[p['id']]);self.write_probe(p,label)
        p['oss_ids'].setdefault(owner,set()).update(self.expected_ids[p['id']]-before)
        self.private(self.state/'all-acknowledged-ids-by-node.private.json',json.dumps({p['id']:{n:sorted(ids) for n,ids in p.get('oss_ids',{}).items()} for p in self.profiles},indent=2))
        self.record(label+':oss_write_read' ,self.until(lambda:self.exact(p)))
        if getattr(self.args,'iceberg',False):
            prepared=json.loads((Path(self.nodes[owner]['data'])/'raft/license-lifecycle.json.prepared').read_text())
            location='file://'+prepared['storage_path']+'/.arc-iceberg-warehouse/arc_license_test.db/events'
            self.record(label+':independent_iceberg_reader_sees_post_handoff_writes',self.until(lambda:self.iceberg_exact(owner,location,self.expected_ids[p['id']]),timeout=60))
            catalogs=self.retained_iceberg_catalogs(p)
            if 'old_iceberg_catalogs' not in p:p['old_iceberg_catalogs']=catalogs
            self.record(label+':predecessor_iceberg_catalogs_unchanged',p['old_iceberg_catalogs']==catalogs)
        files=[]
        for node in p['nodes']:
            data=Path(self.nodes[node]['data'])
            prepared=json.loads((data/'raft/license-lifecycle.json.prepared').read_text())
            namespace=data/Path(prepared['storage_path']).relative_to('/app/data')
            files.extend(str(path) for path in (namespace/'license_test/events').rglob('*.parquet'))
        audit=subprocess.run([self.args.audit_binary],input=json.dumps(files),capture_output=True,text=True)
        retained_ids=set(json.loads(audit.stdout)) if audit.returncode==0 else set()
        expected_all=set(p['sealed_ids'])|set().union(*p['oss_ids'].values())
        self.record(label+':all_acknowledged_ids_retained_across_namespaces',audit.returncode==0 and retained_ids==expected_all,{'expected_unique':len(expected_all),'observed_unique':len(retained_ids),'audit_exit':audit.returncode},note='Physical preservation across retained nodes; current-owner query correctness is checked separately.')
        for n in p['nodes']:
            snap=self.storage_snapshot(n)
            self.record(label+':sqlite_integrity:'+self.nodes[n]['role'],snap['integrity']=='ok')
            before=self.baselines[n]
            retained=all(set(v['row_hashes']).issubset(set(snap['config'].get(k,{}).get('row_hashes',[]))) for k,v in before['config'].items())
            self.record(label+':configuration_preserved:'+self.nodes[n]['role'],retained)
        return True

    def restart_owned(self,names):
        for n in names:
            if not n.startswith(self.run_id+'-') or not self.require_owned('container',n):raise RuntimeError('refuse unrelated restart')
        self.docker('restart','-t','30',*names)

    def suspended_boot(self,p):
        group='trial' if p['license_kind']=='trial' else 'paid'
        key=self.secret('LOCAL-FIXTURE-SUSPENDED-BOOT-'+p['id'].upper())
        stats=self.authority(group,'/stats');profiles=stats['state']['profiles']
        profile={k:p[k] for k in ('tier','features','max_cores','max_machines','license_kind','term_ends_at','expires_at','issued_at','enforce_expiry')}
        profile.update(profile_id='boot-'+p['id'],mode='suspended',activation_mode='suspended')
        profiles[key]=profile;self.control(group,profiles=profiles)
        env=self.base_env(key,self.secret(secrets.token_hex(32)),self.secret(secrets.token_hex(32)),'boot-'+p['id'])
        env.update(SSL_CERT_FILE='/run/fixture-ca.crt',ARC_CLUSTER_ENABLED='false',ARC_COMPACTION_ENABLED='false',ARC_TIERED_STORAGE_ENABLED='false',
                   ARC_CONTINUOUS_QUERY_ENABLED='false',ARC_RETENTION_ENABLED='false',ARC_AUDIT_LOG_ENABLED='false',ARC_GOVERNANCE_ENABLED='false',
                   ARC_DATABASE_THREAD_COUNT='2',ARC_DATABASE_MEMORY_LIMIT='64MB')
        node=self.start_node(p['id'],'boot',env,image=self.args.image,cluster_role='standalone',extra=('-v',str(self.material/'tls.crt')+':/run/fixture-ca.crt:ro'))
        self.wait(node)
        self.current=p['id'];self.record('suspended_boot_starts_oss',self.api(node,'/health')[1].get('license',{}).get('status')=='unlicensed')
        response=self.api(node,'/api/v1/write/line-protocol',f'boot_probe value=1i {time.time_ns()}\n')
        self.record('suspended_boot_write_acked',response[0]==204,response)
        profile['mode']=profile['activation_mode']='valid';self.control(group,profiles=profiles)
        self.record('suspended_boot_automatically_restores_feature_components',self.until(lambda:self.api(node,'/api/v1/queries/active')[0]==200,timeout=45))
        result=self.query_count(node,'boot_probe');self.record('suspended_boot_recovery_preserves_data',result[0]==200 and result[1].get('columns')==['n'] and self.count(result[1])==1,result)

    def run(self):
        retained=self.snapshots();watch=threading.Thread(target=self.watch_originals,daemon=True);watch.start()
        try:
            self.profiles_from_verified_cache();self.setup_resources()
            if getattr(self.args,'shared_unlimited',False):self.s3('/license0-hot','PUT')
            for p in self.profiles:
                self.setup_stack(p)
                for n in p['nodes']:
                    # Cluster role is explicit in the retained per-node env.
                    self.nodes[n]['cluster_role']='reader' if self.nodes[n]['role'].startswith('r') else ('writer' if p['id']=='license0' or self.nodes[n]['role'] in ('w1','w2') else 'compactor')
                    self.baselines[n]=self.storage_snapshot(n)
                self.record('baseline_exact_ids',self.until(lambda:self.exact(p)))
                if getattr(self.args,'iceberg',False):
                    if p['id']=='license0':location='s3://license0-hot/exports/arc_license_test.db/events'
                    elif p['id']=='license1':location='file:///app/data/storage/arc_license_test.db/events'
                    else:location='file:///app/data/storage/custom-export/arc_license_test.db/events'
                    self.record('independent_iceberg_reader_before_expiry',self.until(lambda:any(self.iceberg_exact(n,location,self.expected_ids[p['id']]) for n in p['nodes']),timeout=60))
            term=dt.date.fromisoformat(self.args.term_date)
            paid=[p for p in self.profiles if p['license_kind']=='paid'];trial=[p for p in self.profiles if p['license_kind']=='trial'][0]
            for day in (8,9,10,14):
                self.phase_name='paid-day'+str(day)
                self.control('paid',server_time=(term+dt.timedelta(days=day)).isoformat()+'T00:00:00Z')
                for p in paid:
                    self.current=p['id']
                    self.record('fresh_signed_policy_day_observed_on_every_node',self.until(lambda:all(self.api(n,'/health')[1].get('license',{}).get('desired_policy',{}).get('grace_day')==day for n in p['nodes'])))
                    self.record('durable_one_serving_node_per_role',self.until(lambda:self.reduced(p),timeout=45))
                    self.write_probe(p,'day'+str(day));self.record('data_exact',self.until(lambda:self.exact(p)))
                    if day==8:
                        owner=p['leader']
                        if not self.require_owned('container',owner):raise RuntimeError('unowned stop')
                        self.docker('stop','-t','30',owner)
                        deadline=time.monotonic()+20
                        promoted=[]
                        while time.monotonic()<deadline:
                            promoted += [n for n in p['nodes'] if n!=owner and self.api(n,'/ready/write',timeout=2)[0]==200]
                            time.sleep(1)
                        self.record('day8_no_automatic_replacement',not promoted,sorted(set(promoted)))
                        self.docker('start',owner)
                        self.record('day8_owner_restart_keeps_assignment',self.until(lambda:self.reduced(p),timeout=45))
                    if day>=9:self.record('rbac_mutation_refused',self.api(p['leader'],'/api/v1/rbac/organizations',{'name':'must-refuse-'+self.case_id})[0]==403)
                    if day>=10:self.record('migration_refused',self.api(p['leader'],'/api/v1/tiering/migrate',{'database':'license_test','measurement':'none'})[0]==403)
                self.current=trial['id'];self.record('trial_clock_and_features_unaffected',self.active(trial))
            self.phase_name='paid-final'
            # Block one participant's local seal persistence without changing
            # production code. The controller must retain Raft, then recover
            # after a crash before global release authorization exists.
            blockers={}
            if getattr(self.args,'crash_before_release',False):
                for p in paid:
                    blocker=Path(self.nodes[p['nodes'][-1]]['data'])/'raft/license-lifecycle.json.sealed'
                    blocker.mkdir(mode=0o700);blockers[p['id']]=blocker
            self.control('paid',server_time=(term+dt.timedelta(days=15)).isoformat()+'T00:00:00Z')
            for p in paid:
                if p['id'] in blockers:
                    self.current=p['id'];controller=None
                    def locally_sealed():
                        nonlocal controller
                        for n in p['nodes']:
                            path=Path(self.nodes[n]['data'])/'raft/license-lifecycle.json.sealed'
                            if path.is_file():
                                record=json.loads(path.read_text())
                                if record['controller']==self.nodes[n]['node_id']:
                                    controller=n;return True
                        return False
                    observed=self.until(locally_sealed,timeout=90)
                    self.record('controller_persists_local_seal_before_global_release',observed)
                    authorized=any((Path(self.nodes[n]['data'])/'raft/license-lifecycle.json').exists() for n in p['nodes'])
                    self.record('failed_peer_persistence_blocks_every_raft_off_authorization',observed and not authorized)
                    if observed and not authorized:
                        if not self.require_owned('container',controller):raise RuntimeError('unowned crash')
                        self.docker('kill','--signal=KILL',controller)
                        blockers[p['id']].rmdir()
                        self.docker('start',controller)
                        self.record('controller_crash_before_release_restarts_from_local_seal',True)
                    else:blockers[p['id']].rmdir()
                if self.check_final(p,'expiry'):
                    self.restart_owned(p['nodes']);self.check_final(p,'all-node-restart')
                    self.restart_owned([p['leader']]);self.check_final(p,'owner-restart')
            self.phase_name='trial-final'
            self.control('trial',server_time=self.args.term_date+'T12:00:00Z')
            if self.check_final(trial,'exact-cutoff'):
                self.restart_owned(trial['nodes']);self.check_final(trial,'all-node-restart')
            self.phase_name='reactivation'
            # Move forward only. New term and current authority time are distinct.
            for group,members in [('paid',paid),('trial',[trial])]:
                now=term+dt.timedelta(days=30)
                fields={}
                for p in members:
                    p['term_ends_at']=p['expires_at']=(now+dt.timedelta(days=30)).isoformat()+'T12:00:00Z'
                    fields[p['synthetic_key']]={k:v for k,v in p.items() if k in ('profile_id','tier','features','max_cores','max_machines','license_kind','term_ends_at','expires_at','issued_at','enforce_expiry')}
                self.control(group,profiles=fields,server_time=now.isoformat()+'T00:00:00Z')
                for p in members:
                    self.current=p['id']
                    def recovered():
                        owner=self.final_owner(p)
                        if not owner:return False
                        p['leader']=owner
                        self.expected_ids[p['id']]=set(p['sealed_ids'])|set(p['oss_ids'].get(owner,[]))
                        return self.api(owner,'/api/v1/queries/active')[0]==200
                    self.record('owner_detects_reactivation_and_rebuilds_features',self.until(recovered,timeout=45))
                    self.record('reactivation_preserves_selected_namespace',self.until(lambda:self.exact(p)))
            self.phase_name='suspended-boot'
            for p in self.profiles:self.suspended_boot(p)
        finally:
            self.watch_stop.set();watch.join(timeout=10)
            self.current='protected';self.record('original_services_unchanged',self.original_snapshot()==self.original and not self.watch_failures)
            self.record('prior_synthetic_services_unchanged',self.snapshots()==retained)
            for p in self.profiles:
                if p.get('nodes'):self.collect(p['id'])
            self.write_report()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',required=True);parser.add_argument('--material',required=True);parser.add_argument('--live-state',required=True)
    parser.add_argument('--verified-profiles',required=True);parser.add_argument('--term-date',default='2027-01-01')
    parser.add_argument('--run-id',default='arc-license-lifecycle-v1');parser.add_argument('--image',default='arc-license-lifecycle:fast')
    parser.add_argument('--authority-image',default='arc-license-lifecycle-authority:local');parser.add_argument('--subnet-base',type=int,default=164)
    parser.add_argument('--shared-unlimited',action='store_true');parser.add_argument('--auto-node-ids',action='store_true')
    parser.add_argument('--crash-before-release',action='store_true')
    parser.add_argument('--iceberg',action='store_true')
    parser.add_argument('--audit-binary',required=True,help='Path to the read-only Go ACK auditor binary')
    parser.add_argument('--resume',action='store_true');args=parser.parse_args()
    if args.resume:raise RuntimeError('lifecycle acceptance requires a new isolated project')
    suite=Lifecycle(args);suite.run();raise SystemExit(any(r['result']=='FAIL' for r in suite.results))


if __name__=='__main__':main()
