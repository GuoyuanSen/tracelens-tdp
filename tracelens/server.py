"""Local-only web workbench. No third-party packages or telemetry."""
import argparse
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from . import __version__
from .ai import evidence_packet, generate
from .demo import DemoClient
from .evidence import canonical_target, enrich, remediation_comparison
from .investigation import analyze, compare, markdown_report
from .storage import Storage
from .tdp import AppError, TDPClient, time_range

STATIC = Path(__file__).parent / 'static'


class Application:
    def __init__(self, storage):
        self.storage = storage
        self.token = secrets.token_urlsafe(32)
        self.demo_anchor = int(time.time())

    def client(self):
        config = self.storage.config()
        return DemoClient(self.demo_anchor) if config.get('mode') == 'demo' else TDPClient(config)

    def case_client(self, case, analysis):
        if case['source'].startswith('demo:'):
            if not analysis.get('demo_anchor'):
                raise AppError('这份历史演练未保存案例时间锚点，可继续查看和导出；请新建演练后再复查或关联查询。')
            return DemoClient(analysis['demo_anchor'])
        if self.storage.config().get('mode') == 'demo':
            raise AppError('此档案来自真实 TDP，请切换真实模式后继续调查。')
        client = self.client()
        if client.base != case['source']:
            raise AppError('当前平台与该调查来源不同，请切回原平台。')
        return client

    def get(self, path):
        if path == '/api/bootstrap':
            return {'token': self.token, 'version': __version__, 'config': self.storage.public_config()}
        if path == '/api/cases':
            return self.storage.list()
        if path.startswith('/api/cases/'):
            bits = path.strip('/').split('/')
            case = self.storage.get(bits[2])
            if len(bits) == 3:
                return case
            if len(bits) == 4 and bits[3] == 'export':
                return {'markdown': markdown_report(case)}
            if len(bits) == 4 and bits[3] == 'ai-preview':
                return {'endpoint': self.storage.config().get('ai_url', ''),
                        'packet': evidence_packet(case['snapshots'][-1]['analysis']),
                        'snapshot_id': case['snapshots'][-1]['id']}
        raise AppError('资源不存在。', 404)

    def post(self, path, body):
        if path == '/api/mode':
            return self.storage.save_config({'mode': body.get('mode')})
        if path == '/api/config':
            return self.storage.save_config(body)
        if path == '/api/connection/test':
            now = int(time.time())
            start = now - 86400
            return {'data': self.client().security(start, now), 'checked_at': now}
        if path in ('/api/security', '/api/hosts', '/api/investigate'):
            start, end = time_range(body.get('time_from'), body.get('time_to'))
            client = self.client()
            if path == '/api/security':
                return client.security(start, end)
            if path == '/api/hosts':
                return client.hosts(start, end, body.get('keyword', ''), body.get('page', 1), body.get('severity'))
            ip, kind = canonical_target(body.get('ip', ''))
            analysis = analyze(ip, start, end, client.logs(ip, start, end))
            analysis['mode'] = getattr(client, 'mode', 'live')
            if analysis['mode'] == 'demo':
                analysis['demo_anchor'] = self.demo_anchor
            return self.storage.create(ip, client.base, analysis)
        parts = path.strip('/').split('/')
        if len(parts) != 4 or parts[:2] != ['api', 'cases']:
            raise AppError('操作不存在。', 404)
        case_id, action = parts[2:]
        case = self.storage.get(case_id)
        if action == 'pivot':
            target, kind = canonical_target(body.get('target', ''))
            origin = next((snap for snap in case['snapshots'] if snap['id'] == body.get('snapshot_id')), None)
            if origin is None:
                raise AppError('来源快照不存在。', 409)
            relation = next((item for item in origin['analysis']['related_targets'] if item['target'] == target), None)
            if relation is None:
                raise AppError('此目标不是该快照中的关联对象。')
            client = self.case_client(case, origin['analysis'])
            start, end = origin['analysis']['time_from'], origin['analysis']['time_to']
            analysis = analyze(target, start, end, client.logs(target, start, end))
            analysis['mode'] = getattr(client, 'mode', 'live')
            if analysis['mode'] == 'demo':
                analysis['demo_anchor'] = client.anchor
            return self.storage.create_linked(case_id, origin['id'], target, case['source'], analysis, relation['evidence'])
        if action == 'remediation':
            performed = body.get('performed_at')
            if type(performed) is not int or not 0 < performed <= int(time.time()):
                raise AppError('处置时间必须是已经发生的时间。')
            record = {'id': uuid.uuid4().hex, 'performed_at': performed, 'recorded_at': int(time.time()), 'executed_by_tool': False}
            for key in ('action', 'scope', 'verification'):
                value = body.get(key)
                if not isinstance(value, str) or not value.strip() or len(value) > 3000:
                    raise AppError('请填写处置动作、对象范围及执行依据，每项不超过 3000 字。')
                record[key] = value.strip()
            return self.storage.mutate(case_id, lambda item: item['remediations'].append(record))
        if action == 'note':
            text = body.get('text', '')
            if not isinstance(text, str) or not text.strip() or len(text) > 5000:
                raise AppError('记录内容不能为空，且不能超过 5000 字。')
            return self.storage.mutate(case_id, lambda item: item['notes'].append(
                {'created_at': int(time.time()), 'text': text.strip()}))
        if action == 'status':
            status = body.get('status')
            if status not in ('investigating', 'monitoring', 'closed'):
                raise AppError('调查状态不合法。')
            def update(item):
                item['status'] = status
                item['notes'].append({'created_at': int(time.time()), 'text': '人工更新调查状态为：' + status})
            return self.storage.mutate(case_id, update)
        if action == 'recheck':
            start, end = time_range(body.get('time_from'), body.get('time_to'))
            previous = case['snapshots'][-1]['analysis']
            remediation = None
            baseline = previous
            if body.get('remediation_id'):
                remediation = next((r for r in case['remediations'] if r['id'] == body['remediation_id']), None)
                origin = next((s for s in case['snapshots'] if s['id'] == body.get('baseline_snapshot_id')), None)
                if remediation is None or origin is None:
                    raise AppError('处置记录或基准快照不存在。')
                baseline = origin['analysis']
                if start < remediation['performed_at']:
                    raise AppError('复查窗口不能早于选定的处置时间。')
            elif start < previous['time_to']:
                raise AppError('复查应选择不早于上次查询结束时间的后续窗口。')
            client = self.case_client(case, baseline)
            analysis = analyze(case['ip'], start, end, client.logs(case['ip'], start, end))
            analysis['mode'] = getattr(client, 'mode', 'live')
            if analysis['mode'] == 'demo':
                analysis['demo_anchor'] = client.anchor
            enrich(analysis, case['source'], int(time.time()))
            comparison = remediation_comparison(baseline, analysis, remediation) if remediation else None
            expected = case['snapshots'][-1]['id']
            def append(item):
                if item['snapshots'][-1]['id'] != expected:
                    raise AppError('调查已被其他请求更新，请刷新后再复查。', 409)
                item['snapshots'].append({'id': uuid.uuid4().hex, 'created_at': int(time.time()), 'kind': 'recheck',
                                          'analysis': analysis, 'comparison': compare(baseline, analysis),
                                          'remediation_comparison': comparison,
                                          'baseline_snapshot_id': body.get('baseline_snapshot_id') if remediation else expected})
            return self.storage.mutate(case_id, append)
        if action == 'ai':
            if case['source'].startswith('demo:'):
                raise AppError('案例演练使用本地规则，不发送合成数据到模型服务。')
            snapshot = case['snapshots'][-1]
            config = self.storage.config()
            if body.get('consent') is not True or body.get('endpoint') != config.get('ai_url'):
                raise AppError('请确认将证据摘要发送到当前配置的模型服务。')
            if body.get('snapshot_id') != snapshot['id']:
                raise AppError('证据已变化，请重新预览后再分析。', 409)
            result = generate(config, snapshot['analysis'])
            result['created_at'] = int(time.time())
            def attach(item):
                target = next((s for s in item['snapshots'] if s['id'] == snapshot['id']), None)
                if target is None:
                    raise AppError('调查快照不存在。', 409)
                target['ai'] = result
            return self.storage.mutate(case_id, attach)
        raise AppError('操作不存在。', 404)


class Handler(BaseHTTPRequestHandler):
    server_version = 'TraceLens/' + __version__
    def log_message(self, format, *args):
        # Do not log URLs, payloads, keys, IP evidence, or credentials.
        return

    def send(self, status, content, content_type='application/json; charset=utf-8'):
        payload = content if isinstance(content, bytes) else json.dumps(content, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def check_origin(self):
        port = self.server.server_port
        allowed = {'127.0.0.1:%s' % port, 'localhost:%s' % port}
        host = self.headers.get('Host', '')
        if host not in allowed:
            raise AppError('仅允许本机访问。', 403)
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + host:
            raise AppError('不接受跨站请求。', 403)
        if self.headers.get('Sec-Fetch-Site') in ('cross-site', 'same-site'):
            raise AppError('不接受其他站点的请求。', 403)

    def check_token(self):
        if not hmac.compare_digest(self.headers.get('X-TraceLens-Token', ''), self.server.app.token):
            raise AppError('会话已过期，请刷新页面。', 403)

    def do_GET(self):
        try:
            self.check_origin()
            path = urlsplit(self.path).path
            if path.startswith('/api/'):
                if path != '/api/bootstrap':
                    self.check_token()
                self.send(200, self.server.app.get(path))
                return
            files = {'/': ('index.html', 'text/html; charset=utf-8'),
                     '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                     '/style.css': ('style.css', 'text/css; charset=utf-8'),
                     '/favicon.svg': ('favicon.svg', 'image/svg+xml')}
            if path not in files:
                raise AppError('资源不存在。', 404)
            name, mime = files[path]
            self.send(200, (STATIC / name).read_bytes(), mime)
        except AppError as exc:
            self.send(exc.status, {'error': str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            self.send(500, {'error': '本地服务异常，请检查数据目录与文件权限。'})

    def do_POST(self):
        try:
            self.check_origin()
            self.check_token()
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise AppError('请求必须是 JSON。', 415)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                raise AppError('请求大小不合法。', 413)
            self.connection.settimeout(65)
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise AppError('请求必须是 JSON 对象。')
            self.send(200, self.server.app.post(urlsplit(self.path).path, body))
        except AppError as exc:
            self.send(exc.status, {'error': str(exc)})
        except (ValueError, UnicodeError):
            self.send(400, {'error': '请求格式不正确。'})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            self.send(500, {'error': '本地服务异常，操作未完成；请重试或检查数据目录。'})


def main():
    parser = argparse.ArgumentParser(description='TraceLens for TDP — local investigation workbench')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--data-dir', default=os.environ.get('TRACELENS_DATA_DIR', str(Path.home() / '.local/share/tracelens-tdp')))
    args = parser.parse_args()
    os.umask(0o077)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.app = Application(Storage(args.data_dir))
    print('TraceLens for TDP: http://127.0.0.1:%s' % server.server_port, flush=True)
    print('Local-only service. Press Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
