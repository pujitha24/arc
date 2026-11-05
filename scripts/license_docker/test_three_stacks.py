"""Regression checks for verification oracles; no Docker or network calls."""
import json
from pathlib import Path
import tempfile
import time
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from three_stacks import Matrix


class Oracles(unittest.TestCase):
    def fixture_namespace(self):
        path=Path(__file__).with_name('fixture_server.py')
        namespace={}
        # Load definitions and state, stopping before the server entry point.
        exec(compile(path.read_text().split('\nserver =')[0],str(path),'exec'),namespace)
        return namespace

    def test_retained_authority_event_history_is_bounded(self):
        fixture=self.fixture_namespace()
        for i in range(10010):fixture['EVENTS'].append(i)
        self.assertEqual(len(fixture['EVENTS']),10000)
        self.assertEqual(fixture['EVENTS'][0],10)

    def test_cutoff_counter_survives_success_and_failure_evictions(self):
        fixture=self.fixture_namespace()
        fixture['STATE']['successful_verdict_total']=10000
        fixture['EVENTS'].extend({'successful_verdict':True} for _ in range(10000))
        handler=fixture['Handler'].__new__(fixture['Handler'])
        handler.reply=lambda status,body:(status,body)
        request={'license_key':'LOCAL-FIXTURE-COUNTER','machine_fingerprint':'test-machine'}
        with patch.object(fixture['subprocess'],'run',return_value=SimpleNamespace(stdout=b'test-signature')):
            code,body=handler.license_response(request,False)
        self.assertEqual(code,200);self.assertTrue(body['valid'])
        self.assertEqual(sum(e.get('successful_verdict',False) for e in fixture['EVENTS']),10000)
        self.assertEqual(fixture['STATE']['successful_verdict_total'],10001)
        fixture['STATE']['mode']='503'
        handler.license_response(request,False)
        self.assertEqual(sum(e.get('successful_verdict',False) for e in fixture['EVENTS']),9999)
        self.assertEqual(fixture['STATE']['successful_verdict_total'],10001)

    def test_retained_authority_preserves_monotonic_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            state=Path(folder)/'state.json'
            state.write_text(json.dumps({'server_time':'2026-01-01T00:00:00Z','time_origin':900,
                                         'profiles':{'LOCAL-FIXTURE-TEST':{'tier':'professional'}}}))
            with patch.dict(os.environ,{'FIXTURE_INITIAL_STATE':str(state)}),patch('time.monotonic',return_value=1000):
                fixture=self.fixture_namespace()
                self.assertEqual(fixture['STATE']['time_origin'],900)
                self.assertEqual(fixture['effective_time'](fixture['STATE']).isoformat(),'2026-01-01T00:01:40+00:00')

    def test_retention_checks_data_outcome_not_only_status(self):
        matrix=Matrix.__new__(Matrix);checks={};removed=[False]
        matrix.record=lambda name,passed=None,*args,**kwargs:checks.update({name:passed})
        matrix.until=lambda predicate,**kwargs:predicate()
        def api(node,path,payload=None,**kwargs):
            if path.endswith('/line-protocol'):return 204,''
            if path=='/api/v1/query':return 200,{'columns':['age','n'],'data':[['current',1]] if removed[0] else [['old',1],['current',1]]}
            if 'continuous_queries' in path:return 200,{'status':'completed'}
            removed[0]=True
            return 200,{'deleted_count':1}
        matrix.api=api
        matrix.exercise_jobs({'leader':'node','cq_id':1,'retention_id':1},False)
        self.assertIs(checks.get('retention_policy_effects'),True)

    def test_retention_http_success_cannot_hide_unchanged_old_rows(self):
        matrix=Matrix.__new__(Matrix);checks={}
        matrix.record=lambda name,passed=None,*args,**kwargs:checks.update({name:passed})
        matrix.until=lambda predicate,**kwargs:predicate()
        def api(node,path,payload=None,**kwargs):
            if path.endswith('/line-protocol'):return 204,''
            if path=='/api/v1/query':return 200,{'columns':['age','n'],'data':[['old',1],['current',1]]}
            if 'continuous_queries' in path:return 200,{'status':'completed'}
            return 200,{'deleted_count':0,'files_deleted':0}
        matrix.api=api
        matrix.exercise_jobs({'leader':'node','cq_id':1,'retention_id':1},False)
        self.assertIs(checks.get('retention_policy_effects'),False)

    def test_background_cq_requires_an_execution_new_to_the_window(self):
        matrix=Matrix.__new__(Matrix);checks={};calls=[]
        matrix.record=lambda name,passed=None,*args,**kwargs:checks.update({name:passed})
        matrix.storage_snapshot=lambda node:{'histories':{'continuous_query_executions':['old-row']}}
        def docker(*args):
            calls.append(args)
            return SimpleNamespace(stdout='Scheduled migration cycle starting\n'*len(calls))
        matrix.docker=docker;matrix.watch_failures=[]
        matrix.api=lambda *args,**kwargs:(200,{'executions':[{'execution_id':'cq-sched-old','status':'completed','records_written':1}]})
        with patch('three_stacks.time.monotonic',side_effect=[0,66]):
            matrix.observe_background([{'id':'license0','leader':'node','cq_id':1}],False)
        self.assertIs(checks.get('cq_background_execution_observed'),False)

    def test_background_cq_requires_new_execution_with_output(self):
        for written in (0,1):
            with self.subTest(written=written):
                matrix=Matrix.__new__(Matrix);checks={};calls=[];queries=[]
                matrix.record=lambda name,passed=None,*args,**kwargs:checks.update({name:passed})
                matrix.storage_snapshot=lambda node:{'histories':{'continuous_query_executions':['old-row']}}
                def docker(*args):
                    calls.append(args)
                    return SimpleNamespace(stdout='Scheduled migration cycle starting\n'*len(calls))
                def api(*args,**kwargs):
                    queries.append(args)
                    rows=[{'execution_id':'cq-sched-old','status':'completed','records_written':1}]
                    if len(queries)>1:rows.append({'execution_id':'cq-sched-new','status':'completed','records_written':written})
                    return 200,{'executions':rows}
                matrix.docker=docker;matrix.api=api;matrix.watch_failures=[]
                with patch('three_stacks.time.monotonic',side_effect=[0,66]):
                    matrix.observe_background([{'id':'license0','leader':'node','cq_id':1}],False)
                self.assertIs(checks.get('cq_background_execution_observed'),written>0)

    def test_resume_rejects_later_anchor_that_rewinds_effective_time(self):
        matrix=Matrix.__new__(Matrix);controls=[]
        matrix.args=SimpleNamespace(term_date='2026-11-20')
        matrix.secret=lambda value:value
        matrix.expected_ids={};matrix.profiles=[];matrix.nodes={};matrix.baselines={}
        matrix.record=lambda *args,**kwargs:None
        matrix.authority=lambda *args,**kwargs:{'events':[],'state':{'server_time':'2026-11-19T12:00:00Z','time_origin':time.monotonic()-13*3600}}
        matrix.control=lambda *args,**kwargs:controls.append((args,kwargs))
        with tempfile.TemporaryDirectory() as folder:
            matrix.state=Path(folder)
            (matrix.state/'authorities.private.json').write_text(json.dumps({'paid':{'token':'test'},'trial':{'token':'test'}}))
            (matrix.state/'acknowledged-ids.private.json').write_text('{}')
            with self.assertRaises(RuntimeError):matrix.resume_stacks()
        self.assertEqual(controls,[])

    def test_authority_reported_effective_time_is_preferred(self):
        from three_stacks import authority_now
        result=authority_now({'effective_server_time':'2026-11-20T01:00:00Z',
            'state':{'server_time':'2026-11-19T12:00:00Z','time_origin':time.monotonic()}})
        self.assertEqual(result.isoformat(),'2026-11-20T01:00:00+00:00')

    def test_resume_requires_every_retained_fingerprint_before_mutation(self):
        matrix=Matrix.__new__(Matrix);controls=[]
        matrix.args=SimpleNamespace(term_date='2026-11-20');matrix.secret=lambda value:value
        matrix.authority=lambda *args,**kwargs:{'effective_server_time':'2026-11-19T12:00:00Z'}
        matrix.control=lambda *args,**kwargs:controls.append((args,kwargs))
        matrix.profiles=[{'id':'license0'}]
        matrix.nodes={'one':{'install':'license0','role':'w1'},'two':{'install':'license0','role':'w2'}}
        with tempfile.TemporaryDirectory() as folder:
            matrix.state=Path(folder)
            (matrix.state/'authorities.private.json').write_text(json.dumps({'paid':{'token':'test'},'trial':{'token':'test'}}))
            (matrix.state/'fingerprints.private.json').write_text(json.dumps({'license0':['only-one-fingerprint']}))
            with self.assertRaises(RuntimeError):matrix.resume_stacks()
        self.assertEqual(controls,[])


if __name__=='__main__':unittest.main()
