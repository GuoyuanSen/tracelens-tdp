import copy
import json
import tempfile
import time
import unittest
from unittest.mock import patch
from tracelens.ai import validate_claims, generate
from tracelens.demo import DemoClient
from tracelens.evidence import canonical_target, enrich, remediation_comparison
from tracelens.investigation import analyze, markdown_report
from tracelens.storage import Storage
from tracelens.server import Application
from tracelens.tdp import AppError, TDPClient

NOW = int(time.time())
TARGET = '192.0.2.10'


def event(**values):
    return {'id':'record-1','time':NOW-100,'machine':TARGET,'direction':'lateral',
            'net':{'src_ip':TARGET,'dest_ip':'192.0.2.20'},
            'threat':{'name':'Test rule','type':'exploit','result':'success','severity':4},**values}


def assess(rows, target=TARGET, start=NOW-1000, end=NOW):
    return analyze(target,start,end,{'data':rows,'total':len(rows)})


class RoleAndGroupTests(unittest.TestCase):
    def test_attacker_success_not_victim_compromise(self):
        a=assess([event(attacker=TARGET,victim='192.0.2.20')])
        self.assertEqual(a['summary']['success'],0)
        self.assertEqual(a['summary']['related_success'],1)
        self.assertEqual(a['evidence'][0]['role']['security'],'attacker')

    def test_explicit_victim_is_required(self):
        self.assertEqual(assess([event()])['summary']['success'],0)
        a=assess([event(attacker='192.0.2.20',victim=TARGET)])
        self.assertEqual(a['summary']['success'],1)

    def test_conflicting_security_roles_are_unknown_for_findings(self):
        a=assess([event(attacker=TARGET,victim=TARGET)])
        self.assertEqual(a['evidence'][0]['role']['security'],'conflict')
        self.assertEqual(a['summary']['success'],0)

    def test_destination_of_c2_is_not_infected_source(self):
        row=event(direction='out',net={'src_ip':'192.0.2.20','dest_ip':TARGET},
                  threat={'type':'c2','result':'success','is_connected':1})
        self.assertEqual(assess([row])['summary']['remote'],0)

    def test_real_source_and_ipv6_canonicalization(self):
        row=event(machine='2001:db8::1',net={'src_ip':'2001:0db8:0:0:0:0:0:1','dest_ip':'2001:db8::2'})
        self.assertEqual(assess([row],'2001:db8::1')['evidence'][0]['role']['network'],'source')

    def test_grouping_preserves_counts_times_and_refs(self):
        rows=[event(id='a',time=NOW-100),event(id='b',time=NOW-20)]
        a=assess(rows)
        self.assertEqual(a['summary']['groups'],1)
        self.assertEqual(a['groups'][0]['count'],2)
        self.assertEqual(a['groups'][0]['first_seen'],NOW-100)
        self.assertEqual(a['groups'][0]['evidence'],['E001','E002'])
        self.assertEqual(len(a['evidence']),2)

    def test_different_results_or_nodes_do_not_merge(self):
        original=event()
        failed=event(id='failed',threat={'name':'Test rule','type':'exploit','result':'failed','severity':4})
        other=event(id='sensor',device_id='other-node')
        self.assertEqual(assess([original,failed,other])['summary']['groups'],3)

    def test_conflicting_security_roles_never_merge(self):
        a=assess([event(id='victim',victim=TARGET),event(id='attacker',attacker=TARGET)])
        self.assertEqual(a['summary']['groups'],2)

    def test_provenance_hash_changes_on_raw_change(self):
        a=enrich(assess([event()]),'https://tdp.example.com',NOW)
        b=enrich(assess([event(time=NOW-101)]),'https://tdp.example.com',NOW)
        p=a['evidence'][0]['provenance']
        self.assertEqual(p['source'],'https://tdp.example.com')
        self.assertEqual(len(p['sha256']),64)
        self.assertNotEqual(p['sha256'],b['evidence'][0]['provenance']['sha256'])

    def test_explicit_partial_and_duplicate_count(self):
        row=event()
        a=analyze(TARGET,NOW-1000,NOW,{'data':[row,row],'total':10})
        self.assertTrue(a['coverage']['partial'])
        self.assertEqual(a['coverage']['duplicate_rows'],1)

    def test_domain_is_indicator_not_host_role(self):
        a=assess([event(data='c2.example.com')],'c2.example.com')
        self.assertEqual(a['target_kind'],'domain')
        self.assertEqual(a['evidence'][0]['role']['network'],'indicator')
        self.assertEqual(a['summary']['success'],0)

    def test_target_validation_blocks_sql_and_urls(self):
        for value in ["a.com' OR 1=1",'https://example.com/path','a..com','bad_host.com','999.999.1.1']:
            with self.assertRaises(AppError):canonical_target(value)

    @patch('tracelens.tdp.request_json',return_value={'response_code':0,'data':{'data':[],'total':0}})
    def test_domain_query_exact_contract(self, request):
        client=TDPClient({'tdp_url':'https://tdp.example.com','tdp_key':'test-key','tdp_secret':'test-secret'})
        client.logs('Example.COM',NOW-100,NOW)
        self.assertEqual(request.call_args.args[1]['sql'],"(data = 'example.com' OR threat.ioc = 'example.com')")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Storage(self.temp.name);self.app=Application(self.store)
        self.app.post('/api/mode',{'mode':'demo'})
        self.case=self.app.post('/api/investigate',{'ip':TARGET,'time_from':NOW-86400,'time_to':NOW})
    def tearDown(self):self.temp.cleanup()

    def test_pivot_creates_bidirectional_links(self):
        snap=self.case['snapshots'][0]
        child=self.app.post('/api/cases/'+self.case['id']+'/pivot',{'target':'c2-demo.example.com','snapshot_id':snap['id']})
        parent=self.store.get(self.case['id'])
        self.assertEqual(child['links'][0]['case_id'],parent['id'])
        self.assertEqual(parent['links'][0]['case_id'],child['id'])
        self.assertEqual(child['snapshots'][0]['analysis']['time_from'],snap['analysis']['time_from'])
        self.assertTrue(child['links'][0]['evidence'])
        self.assertEqual(child['snapshots'][0]['analysis']['target_kind'],'domain')

    def test_pivot_rejects_fabricated_target(self):
        with self.assertRaises(AppError):self.app.post('/api/cases/'+self.case['id']+'/pivot',{'target':'unseen.example.com','snapshot_id':self.case['snapshots'][0]['id']})
        self.assertEqual(len(self.store.list()),1)

    def test_remediation_requires_actual_time_and_basis(self):
        path='/api/cases/'+self.case['id']+'/remediation'
        for payload in [{'performed_at':NOW+3600,'action':'x','scope':'x','verification':'x'},
                        {'performed_at':NOW,'action':'x','scope':'x','verification':''}]:
            with self.assertRaises(AppError):self.app.post(path,payload)

    def test_recheck_binds_action_and_baseline(self):
        path='/api/cases/'+self.case['id']
        saved=self.app.post(path+'/remediation',{'performed_at':NOW-5000,'action':'演练阻断确认','scope':TARGET,'verification':'演练工单，不是真实执行'})
        record=saved['remediations'][0]
        self.assertFalse(record['executed_by_tool'])
        body={'time_from':NOW-5000,'time_to':NOW,'remediation_id':record['id'],'baseline_snapshot_id':self.case['snapshots'][0]['id']}
        result=self.app.post(path+'/recheck',body)
        comparison=result['snapshots'][-1]['remediation_comparison']
        self.assertEqual(comparison['remediation_id'],record['id'])
        self.assertGreater(comparison['baseline_evidence'],0)
        self.assertIn('用户声明',markdown_report(result))
        with self.assertRaises(AppError):self.app.post(path+'/recheck',{**body,'time_from':NOW-6000})

    def test_legacy_snapshot_upgrade_preserves_raw_and_refs(self):
        original=copy.deepcopy(self.case)
        def make_old(case):
            a=case['snapshots'][0]['analysis'];a.pop('analysis_version');a.pop('groups')
        self.store.mutate(self.case['id'],make_old)
        upgraded=self.store.get(self.case['id'])
        self.assertEqual(upgraded['snapshots'][0]['analysis']['evidence'][0]['raw'],original['snapshots'][0]['analysis']['evidence'][0]['raw'])
        self.assertEqual(upgraded['snapshots'][0]['analysis']['evidence'][0]['ref'],'E001')
        self.assertEqual(upgraded['snapshots'][0]['analysis']['analysis_version'],2)

    def test_legacy_demo_without_anchor_cannot_invent_new_timestamps(self):
        def remove_anchor(case):case['snapshots'][0]['analysis'].pop('demo_anchor')
        self.store.mutate(self.case['id'],remove_anchor)
        with self.assertRaises(AppError):self.app.post('/api/cases/'+self.case['id']+'/pivot',{'target':'192.0.2.20','snapshot_id':self.case['snapshots'][0]['id']})

    def test_demo_contrasts(self):
        client=DemoClient(NOW)
        normal=assess(client.logs('192.0.2.30',NOW-86400,NOW)['data'],'192.0.2.30',NOW-86400,NOW)
        self.assertEqual(normal['summary']['success'],0)
        self.assertTrue(any('training_context' in e['raw'] for e in normal['evidence']))
        uncertain=analyze('192.0.2.40',NOW-86400,NOW,client.logs('192.0.2.40',NOW-86400,NOW))
        self.assertTrue(uncertain['coverage']['partial'])
        self.assertTrue(all(h['state']=='证据不足' for h in uncertain['hypotheses']))


class ComparisonAndAITests(unittest.TestCase):
    def test_repeated_behavior_and_changed_peer(self):
        old=assess([event()]);new=assess([event(id='same',time=NOW-10),event(id='changed',time=NOW-5,net={'src_ip':TARGET,'dest_ip':'192.0.2.99'})])
        result=remediation_comparison(old,new,{'id':'r','performed_at':NOW-50,'action':'封禁测试'})
        self.assertEqual(len(result['repeated_evidence']),1)
        self.assertEqual(len(result['changed_peer_evidence']),1)

    def test_missing_baseline_cannot_prove_no_recurrence(self):
        result=remediation_comparison(assess([]),assess([]),{'id':'r','performed_at':NOW-50,'action':'检查'})
        self.assertTrue(result['baseline_missing'])
        self.assertIn('不能',result['statement'])

    def claim(self,**overrides):
        return {'conclusion':'需要核查','status':'supported','support':['E001'],'against':[],
                'gaps':['缺少终端记录'],'next_steps':['核查终端'],**overrides}

    def test_structured_ai_accepts_valid_and_rejects_missing_or_fake_refs(self):
        valid={'E001','E002'}
        self.assertEqual(len(validate_claims(json.dumps({'claims':[self.claim()]}),valid)),1)
        bad=[self.claim(support=['E999']),self.claim(gaps=[]),self.claim(against=['E001']),
             self.claim(status='conflicted',against=[]),self.claim(conclusion='参见 E999'),self.claim(support=[])]
        for claim in bad:
            with self.assertRaises(AppError):validate_claims(json.dumps({'claims':[claim]}),valid)

    @patch('tracelens.ai.request_json')
    def test_valid_ai_result_remains_semantically_unverified(self,request):
        request.return_value={'choices':[{'finish_reason':'stop','message':{'content':json.dumps({'claims':[self.claim()]})}}]}
        result=generate({'ai_url':'https://model.example.com/v1','ai_model':'test-model'},assess([event()]))
        self.assertTrue(result['structure_valid']);self.assertFalse(result['verified'])
        self.assertEqual(len(result['claims']),1)

if __name__=='__main__':unittest.main()
