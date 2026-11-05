"""Stateful activation fixture contracts; no network/Docker operations."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class ActivationFixture(unittest.TestCase):
    def setUp(self):
        path=Path(__file__).with_name('fixture_server.py');self.fixture={}
        exec(compile(path.read_text().split('\nserver =')[0],str(path),'exec'),self.fixture)
        self.state=self.fixture['STATE'];self.key='LOCAL-FIXTURE-A'
        self.state['strict_profiles']=True
        self.state['profiles']={self.key:{'profile_id':'a','reactivation_epoch':1,'reactivation_reason':'missing_activation','test_phase':'phase-one'},
                               'LOCAL-FIXTURE-B':{'profile_id':'b'}}
        self.handler=self.fixture['Handler'].__new__(self.fixture['Handler'])
        self.handler.reply=lambda status,body:(status,body)

    def request(self,activate=False,key=None,fp='first'):
        with patch.object(self.fixture['subprocess'],'run',return_value=SimpleNamespace(stdout=b'test-signature')):
            return self.handler.license_response({'license_key':key or self.key,'machine_fingerprint':fp},activate)

    def test_missing_activation_is_consumed_only_for_the_activated_machine(self):
        self.assertEqual(self.request()[1],{'valid':False,'error':'machine not activated for this license'})
        self.assertTrue(self.request(True)[1]['success'])
        self.assertTrue(self.request()[1]['valid'])
        self.assertFalse(self.request(fp='second')[1]['valid'])
        self.assertTrue(self.request(key='LOCAL-FIXTURE-B')[1]['valid'])

    def test_revocation_requires_one_activation_then_plain_verification(self):
        self.state['profiles'][self.key]['reactivation_reason']='revoked_activation'
        self.assertEqual(self.request()[1]['error'],'activation has been revoked')
        self.assertTrue(self.request(True)[1]['success'])
        self.assertTrue(self.request()[1]['valid'])
        self.assertTrue(self.request()[1]['valid'])

    def test_temporary_activation_failure_does_not_consume_epoch(self):
        self.state['profiles'][self.key]['activation_mode']='503'
        self.assertEqual(self.request(True)[0],503)
        self.assertFalse(self.request()[1]['valid'])
        self.state['profiles'][self.key]['activation_mode']='valid'
        self.assertTrue(self.request(True)[1]['success'])
        self.assertTrue(self.request()[1]['valid'])

    def test_suspended_activation_is_definitive_but_recoverable(self):
        self.state['profiles'][self.key]['activation_mode']='suspended'
        self.assertEqual(self.request(True)[1],{'success':False,'error':'license is suspended'})
        self.assertFalse(self.request()[1]['valid'])
        self.state['profiles'][self.key]['activation_mode']='valid'
        self.assertTrue(self.request(True)[1]['success'])
        self.assertTrue(self.request()[1]['valid'])

    def test_invalid_response_does_not_consume_epoch(self):
        for mode in ('bad_signature','bad_time_signature','omit_time'):
            with self.subTest(mode=mode):
                self.state['profiles'][self.key]['activation_mode']=mode
                self.request(True)
                self.assertFalse(self.request()[1]['valid'])

    def test_concurrent_control_change_does_not_consume_a_stale_epoch(self):
        def sign(*args,**kwargs):
            self.state['profiles'][self.key]['reactivation_epoch']=2
            return SimpleNamespace(stdout=b'test-signature')
        with patch.object(self.fixture['subprocess'],'run',side_effect=sign):
            self.handler.license_response({'license_key':self.key,'machine_fingerprint':'first'},True)
        self.assertFalse(self.request()[1]['valid'])
        self.assertTrue(self.request(True)[1]['success'])
        self.assertTrue(self.request()[1]['valid'])

    def test_rejection_events_have_phase_reason_and_server_time(self):
        self.state['profiles'][self.key]['mode']='suspended'
        self.request()
        event=self.fixture['EVENTS'][-1]
        self.assertEqual(event.get('test_phase'),'phase-one')
        self.assertEqual(event.get('rejection_reason'),'license is suspended')
        self.assertTrue(event.get('effective_server_time'))


class RecoveryOracles(unittest.TestCase):
    def test_primary_monitor_is_not_automatic_failover_permission(self):
        from normalization import failover_configuration
        self.assertIs(failover_configuration('{"message":"Writer primary election initialized","auto_failover":false}'),False)
        self.assertIs(failover_configuration('{"message":"Writer primary election initialized","auto_failover":true}'),True)
        self.assertIsNone(failover_configuration('{"writer_failover":{"running":true}}'))
        self.assertIsNone(failover_configuration('not JSON'))


class PersistAuthorityState(unittest.TestCase):
    def test_reused_authority_persists_to_its_actual_owned_mount(self):
        import json
        import tempfile
        from normalization import Normalization
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);saved=root/'older-run'/'authority-initial-paid.json'
            saved.parent.mkdir();saved.write_text('old');saved.chmod(0o600)
            suite=Normalization.__new__(Normalization);suite.run_id='synthetic'
            suite.fixture=root/'three-stacks';suite.authorities={'paid':{'name':'synthetic-paid-authority'}}
            suite.require_owned=lambda *args:True
            suite.docker=lambda *args:SimpleNamespace(stdout=json.dumps([{'Mounts':[{'Destination':'/initial-state.json','Type':'bind','Source':str(saved)}]}]))
            suite.authority=lambda *args:{'state':{'clock_origin':123,'activation_epochs':{'key':{'fp':2}}}}
            suite.persist_authority_state('paid')
            self.assertEqual(json.loads(saved.read_text())['clock_origin'],123)
            self.assertEqual(saved.stat().st_mode & 0o777,0o600)
            suite.fixture=root/'unrelated'/'three-stacks'
            with self.assertRaises(RuntimeError):suite.persist_authority_state('paid')
            suite.fixture=root/'three-stacks';suite.require_owned=lambda *args:False
            with self.assertRaises(RuntimeError):suite.persist_authority_state('paid')


class AuthorityRollback(unittest.TestCase):
    def test_failed_replacement_restores_original_container_and_network(self):
        import datetime as dt
        import json
        from normalization import Normalization
        suite=Normalization.__new__(Normalization)
        suite.run_id='synthetic';suite.case_id='case';suite.label='arc-license-tests=synthetic'
        suite.args=SimpleNamespace(refresh_authority_image='local-fixture')
        suite.authorities={'paid':{'name':'synthetic-paid-authority'}}
        suite.state=Path('/private/output');suite.fixture=Path('/private/fixtures');suite.material=Path('/private/material')
        suite.require_owned=lambda *args:True;suite.persist_authority_state=lambda *args:None;suite.private=lambda *args:None
        suite.authority=lambda *args:{'state':{}}
        old={'Id':'original-id','Name':'/synthetic-paid-authority','NetworkSettings':{'Networks':{'synthetic-license0':{'IPAddress':'10.0.0.2','Aliases':['enterprise.basekick.net']}}}}
        calls=[];attached=dict(old['NetworkSettings']['Networks']);name=old['Name']
        def docker(*args):
            nonlocal name
            calls.append(args)
            if args[0]=='inspect':
                return SimpleNamespace(stdout=json.dumps([{**old,'Name':name,'NetworkSettings':{'Networks':dict(attached)}}]))
            if args[0]=='create':raise RuntimeError('replacement image cannot start')
            if args[:2]==('network','disconnect'):attached.pop(args[2])
            if args[:2]==('network','connect'):attached[args[-2]]=old['NetworkSettings']['Networks'][args[-2]]
            if args[0]=='rename':name='/'+args[2]
            return SimpleNamespace(stdout='')
        suite.docker=docker
        with patch('normalization.authority_now',return_value=dt.datetime.now(dt.timezone.utc)):
            with self.assertRaisesRegex(RuntimeError,'replacement image'):suite.refresh_authorities()
        self.assertEqual(name,old['Name'])
        self.assertEqual(attached,old['NetworkSettings']['Networks'])
        self.assertIn(('start','original-id'),calls)
        self.assertNotIn(('rm','original-id'),calls)
        self.assertEqual(calls[0],('image','inspect','local-fixture'))


if __name__=='__main__':unittest.main()
