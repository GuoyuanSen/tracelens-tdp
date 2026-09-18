import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from tracelens.ai import evidence_packet, generate
from tracelens.investigation import analyze, compare, markdown_report
from tracelens.server import Application, Handler, ThreadingHTTPServer
from tracelens.storage import Storage
from tracelens.tdp import AppError, NoRedirect, TDPClient, sign_query, time_range, validate_url

TARGET = '192.0.2.10'
NOW = int(time.time())
CONFIG = {'tdp_url': 'https://tdp.example.com', 'tdp_key': 'unit-test-key', 'tdp_secret': 'unit-test-secret'}

def record(identifier='one', **changes):
    return {'id': identifier, 'time': NOW-50, 'machine': TARGET, 'direction': 'lateral',
            'threat': {'name':'Synthetic test event', 'severity':4,'result':'success','type':'exploit'},
            'net': {'src_ip':TARGET,'dest_ip':'192.0.2.20'}, **changes}


def analysis(rows=None, total=None):
    rows = [record()] if rows is None else rows
    return analyze(TARGET, NOW-100, NOW, {'data': rows, 'total':len(rows) if total is None else total})


class AdapterTests(unittest.TestCase):
    def test_signature_is_urlsafe_and_uses_one_timestamp(self):
        expected=base64.urlsafe_b64encode(hmac.new(b'secret',b'key123',hashlib.sha256).digest()).decode().rstrip('=')
        self.assertEqual(sign_query('key','secret',123), {'api_key':'key','auth_timestamp':'123','sign':expected})

    def test_invalid_origins(self):
        for url in ['http://example.com', 'https://user:pass@example.com', 'https://example.com?a=b',
                    'https://example.com/#frag','https://example.com/path','https://example.com:abc']:
            with self.subTest(url=url), self.assertRaises(AppError): validate_url(url,True)

    def test_range_limits(self):
        for start,end in [(0,0),(200,100),(0,32*86400),('0',10),(True,10)]:
            with self.assertRaises(AppError):time_range(start,end)

    @patch('tracelens.tdp.request_json')
    def test_only_allowlisted_endpoints(self, request):
        with self.assertRaises(AppError): TDPClient(CONFIG).call('/delete',{})
        request.assert_not_called()

    @patch('tracelens.tdp.request_json')
    def test_ip_injection_never_reaches_network(self, request):
        with self.assertRaises(AppError): TDPClient(CONFIG).logs("1.2.3.4' OR 1=1",NOW-100,NOW)
        request.assert_not_called()

    @patch('tracelens.tdp.request_json', return_value={'response_code':0,'data':{'data':[],'total':0}})
    def test_log_query_contract(self, request):
        TDPClient(CONFIG).logs(TARGET,NOW-100,NOW)
        url,body=request.call_args.args
        self.assertIn('/api/v1/log/searchBySql?',url)
        self.assertNotIn('unit-test-secret',url)
        self.assertEqual(body['net_data_type'],['attack','risk','action'])
        self.assertIn("net.dest_ip = '192.0.2.10'",body['sql'])

    @patch('tracelens.tdp.request_json', return_value={'response_code':-1,'verbose_msg':'secret echoed by upstream'})
    def test_remote_errors_dont_echo_credentials(self, request):
        with self.assertRaises(AppError) as error: TDPClient(CONFIG).security(NOW-100,NOW)
        self.assertNotIn('echoed',str(error.exception))

    def test_redirects_not_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.example.com'))


class EvidenceTests(unittest.TestCase):
    def test_empty_evidence_never_means_safe(self):
        data=analysis([])
        self.assertTrue(all(h['state']=='证据不足' for h in data['hypotheses']))
        self.assertIn('未找到可用证据',' '.join(data['gaps']))

    def test_direction_does_not_assert_success(self):
        data=analysis([record(threat={'result':'unknown','name':'Attempt'})])
        self.assertEqual(data['summary']['success'],0)
        self.assertEqual(data['summary']['lateral'],1)
        self.assertIn('不能',data['hypotheses'][2]['finding'])

    def test_foreign_and_out_of_window_records_are_removed(self):
        data=analysis([record(),record('old',time=1),record('other',machine='198.51.100.1',net={})])
        self.assertEqual(len(data['evidence']),1)
        self.assertEqual(data['coverage']['discarded'],2)
        self.assertTrue(data['coverage']['partial'])

    def test_citations_are_stable_after_sorting_and_duplicates(self):
        later=record('later',time=NOW-10,victim=TARGET)
        earlier=record('earlier',time=NOW-80,victim=TARGET)
        data=analysis([later,earlier,earlier])
        self.assertEqual([(e['ref'],e['id']) for e in data['evidence']],[('E001','earlier'),('E002','later')])
        self.assertEqual(data['hypotheses'][0]['evidence'],['E001','E002'])

    def test_truncated_results_are_explicit(self):
        data=analysis([record()],total=1000)
        self.assertTrue(data['coverage']['partial'])
        self.assertIn('不完整',' '.join(data['gaps']))

    def test_unknown_total_is_not_assumed_complete(self):
        data=analyze(TARGET,NOW-100,NOW,{'data':[record()]})
        self.assertTrue(data['coverage']['partial'])

    def test_string_false_not_treated_as_connected(self):
        data=analysis([record(direction='out',threat={'type':'c2','is_connected':'0'})])
        self.assertEqual(data['summary']['remote'],0)

    def test_flat_fields_supported(self):
        row={'id':'x','time':NOW-1,'machine':TARGET,'threat.name':'Flat','threat.result':'success','net.src_ip':TARGET}
        self.assertEqual(analysis([row])['evidence'][0]['name'],'Flat')

    def test_comparison_does_not_claim_remediation(self):
        result=compare(analysis(),analysis([]))
        self.assertFalse(result['comparable'])
        self.assertIn('不能',result['statement'])

    def test_ai_packet_excludes_raw_payloads(self):
        data=analysis([record(payload='private-payload',assets={'owner':'private-owner'})])
        packet=json.dumps(evidence_packet(data))
        self.assertNotIn('private-payload',packet)
        self.assertNotIn('private-owner',packet)

    @patch('tracelens.ai.request_json', return_value={'choices':[{'message':{'content':'结论 [E999]'},'finish_reason':'stop'}]})
    def test_hallucinated_references_are_flagged(self,request):
        with self.assertRaises(AppError):
            generate({'ai_url':'https://model.example.com/v1','ai_model':'configured-model'},analysis())


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Storage(self.temp.name)
        self.store.save_config(CONFIG)
        self.app=Application(self.store)
        self.case=self.store.create(TARGET,CONFIG['tdp_url'],analysis())

    def tearDown(self): self.temp.cleanup()

    def test_secret_fields_never_returned(self):
        result=json.dumps(self.store.public_config())
        self.assertNotIn('unit-test-key',result)
        self.assertNotIn('unit-test-secret',result)
        self.assertTrue(self.store.public_config()['tdp_key_set'])
        self.assertEqual(os.stat(self.store.config_path).st_mode&0o777,0o600)

    def test_blank_secret_preserves_value(self):
        self.store.save_config({'tdp_key':'','tdp_secret':''})
        self.assertEqual(self.store.config()['tdp_key'],CONFIG['tdp_key'])

    def test_change_host_requires_new_credentials(self):
        with self.assertRaises(AppError):self.store.save_config({'tdp_url':'https://other.example.com'})
        self.assertEqual(self.store.config()['tdp_url'],CONFIG['tdp_url'])

    def test_environment_locked_field(self):
        with patch.dict(os.environ,{'TRACELENS_TDP_KEY':'from-env'}):
            with self.assertRaises(AppError):self.store.save_config({'tdp_key':'new'})
            self.assertIn('tdp_key',self.store.public_config()['locked'])

    def test_reopen_preserves_case(self):
        reopened=Storage(self.temp.name)
        self.assertEqual(reopened.get(self.case['id'])['ip'],TARGET)

    def test_parallel_notes_are_not_lost(self):
        def add(i):self.app.post('/api/cases/'+self.case['id']+'/note',{'text':str(i)})
        with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(add,range(20)))
        self.assertEqual(len(self.store.get(self.case['id'])['notes']),20)

    def test_recheck_blocks_overlapping_windows(self):
        with self.assertRaises(AppError):self.app.post('/api/cases/'+self.case['id']+'/recheck',{'time_from':NOW-1,'time_to':NOW+10})

    @patch('tracelens.server.TDPClient')
    def test_recheck_appends_and_preserves_initial(self,client):
        client.return_value.mode='live';client.return_value.base=CONFIG['tdp_url'];client.return_value.logs.return_value={'data':[],'total':0}
        result=self.app.post('/api/cases/'+self.case['id']+'/recheck',{'time_from':NOW,'time_to':NOW+10})
        self.assertEqual(len(result['snapshots']),2)
        self.assertEqual(result['snapshots'][0]['analysis']['summary']['events'],1)
        self.assertIn('不能',result['snapshots'][1]['comparison']['statement'])

    @patch('tracelens.server.generate')
    def test_ai_requires_explicit_consent_and_current_snapshot(self,generate_mock):
        for body in [{},{'consent':True,'endpoint':'https://other.example.com','snapshot_id':'old'}]:
            with self.assertRaises(AppError):self.app.post('/api/cases/'+self.case['id']+'/ai',body)
        generate_mock.assert_not_called()

    def test_export_includes_evidence_and_notes(self):
        self.app.post('/api/cases/'+self.case['id']+'/note',{'text':'Synthetic analyst note'})
        text=markdown_report(self.store.get(self.case['id']))
        self.assertIn('[E001]',text)
        self.assertIn('Synthetic analyst note',text)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.server.app=Application(Storage(cls.temp.name))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.temp.cleanup()

    def test_static_and_bootstrap(self):
        with urllib.request.urlopen(self.base+'/') as response:
            self.assertIn(b'TraceLens',response.read())
            self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        with urllib.request.urlopen(self.base+'/api/bootstrap') as response:
            self.assertIn('token',json.load(response))

    def test_api_requires_session_header(self):
        with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(self.base+'/api/cases')
        self.assertEqual(error.exception.code,403)

    def test_cross_origin_rejected_even_with_token(self):
        req=urllib.request.Request(self.base+'/api/config',data=b'{}',headers={
            'Origin':'https://evil.example.com','Content-Type':'application/json','X-TraceLens-Token':self.server.app.token})
        with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(req)
        self.assertEqual(error.exception.code,403)

    def test_dns_rebinding_host_rejected(self):
        req=urllib.request.Request(self.base+'/api/bootstrap',headers={'Host':'evil.example.com'})
        with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(req)
        self.assertEqual(error.exception.code,403)

    def test_paths_cannot_read_data_or_source(self):
        for path in ['/../storage.py','/config.json','/.env']:
            with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(self.base+path)
            self.assertEqual(error.exception.code,404)



class DemoTests(unittest.TestCase):
    def test_demo_needs_no_credentials_or_network(self):
        from tracelens.demo import DemoClient
        client=DemoClient(NOW)
        with patch('tracelens.tdp.request_json', side_effect=AssertionError('Network must not be used')):
            self.assertEqual(len(client.hosts(NOW-86400,NOW)['items']),4)
            data=analyze(TARGET,NOW-86400,NOW,client.logs(TARGET,NOW-86400,NOW))
            self.assertGreater(data['summary']['remote'],0)
            self.assertTrue(all(e['raw']['synthetic'] for e in data['evidence']))

    def test_demo_applies_time_filters(self):
        from tracelens.demo import DemoClient
        self.assertEqual(DemoClient(NOW).logs(TARGET,NOW,NOW+60)['data'],[])

    def test_mode_switch_preserves_live_credentials_and_labels_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Storage(directory);store.save_config(CONFIG)
            app=Application(store)
            result=app.post('/api/mode',{'mode':'demo'})
            self.assertTrue(result['ready']);self.assertFalse(result['ai_ready'])
            case=app.post('/api/investigate',{'ip':TARGET,'time_from':NOW-86400,'time_to':NOW+1})
            self.assertTrue(case['source'].startswith('demo:'))
            self.assertIn('合成数据演练',markdown_report(case))
            with self.assertRaises(AppError):app.post('/api/cases/'+case['id']+'/ai',{'consent':True})
            app.post('/api/mode',{'mode':'live'})
            self.assertEqual(store.config()['tdp_secret'],CONFIG['tdp_secret'])

    def test_invalid_mode_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AppError):Storage(directory).save_config({'mode':'silent-fallback'})

    def test_demo_recheck_uses_original_anchor_after_switch_to_live(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Storage(directory);app=Application(store)
            app.post('/api/mode',{'mode':'demo'})
            case=app.post('/api/investigate',{'ip':TARGET,'time_from':NOW-86400,'time_to':NOW})
            anchor=case['snapshots'][0]['analysis']['demo_anchor']
            app.post('/api/mode',{'mode':'live'})
            app.demo_anchor=anchor+3600
            with patch('tracelens.tdp.request_json',side_effect=AssertionError('Must stay offline')):
                result=app.post('/api/cases/'+case['id']+'/recheck',{'time_from':NOW,'time_to':NOW+30})
            self.assertEqual(result['snapshots'][-1]['analysis']['demo_anchor'],anchor)
            self.assertEqual(result['snapshots'][-1]['analysis']['summary']['events'],0)
