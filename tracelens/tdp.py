"""Read-only TDP adapter. Credentials never appear in returned errors or URLs."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class AppError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(value, origin_only=False):
    if not isinstance(value, str) or len(value) > 2048:
        raise AppError('请输入有效的 HTTPS 地址。')
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise AppError('地址必须使用 HTTPS，不能包含凭据、查询参数或片段。')
    try:
        parsed.port
    except ValueError:
        raise AppError('端口格式不正确。') from None
    if origin_only and parsed.path not in ('', '/'):
        raise AppError('TDP 地址只填写协议、主机和可选端口，不包含路径。')
    return value.strip().rstrip('/')


def time_range(start, end):
    if type(start) is not int or type(end) is not int or start < 0 or end <= start:
        raise AppError('请选择有效的开始和结束时间。')
    if end - start > 31 * 86400:
        raise AppError('单次调查范围不能超过 31 天。')
    if end > int(time.time()) + 86400:
        raise AppError('结束时间超出允许范围。')
    return start, end


def sign_query(api_key, secret, timestamp):
    timestamp = str(timestamp)
    digest = hmac.new(secret.encode(), (api_key + timestamp).encode(), hashlib.sha256).digest()
    return {'api_key': api_key, 'auth_timestamp': timestamp,
            'sign': base64.urlsafe_b64encode(digest).decode().rstrip('=')}


def request_json(url, body, headers=None, timeout=30):
    try:
        context = ssl.create_default_context(cafile=os.environ.get('TRACELENS_CA_FILE') or None)
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
        req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(),
                                     headers={'Content-Type': 'application/json', **(headers or {})}, method='POST')
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise AppError('返回数据超过 8 MB，请缩小查询时间范围。', 502)
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        messages = {401: '鉴权失败，请检查凭据。', 403: '访问被拒绝，请检查接口权限。',
                    404: '接口不存在，请检查平台版本与地址。', 429: '请求过于频繁，请稍后重试。'}
        raise AppError(messages.get(exc.code, '远端返回 HTTP %s，请检查服务状态。' % exc.code), 502) from None
    except (ssl.SSLError, urllib.error.URLError, OSError, socket.timeout):
        raise AppError('连接失败：请检查地址、网络、证书和代理；内部 CA 可通过 TRACELENS_CA_FILE 配置。', 502) from None
    except (ValueError, UnicodeError):
        raise AppError('远端未返回有效 JSON，请检查地址是否指向正确的 API。', 502) from None


class TDPClient:
    mode = 'live'
    PATHS = {'security': '/api/v1/dashboard/security',
             'hosts': '/api/v1/host/getFallHostSumList',
             'logs': '/api/v1/log/searchBySql'}

    def __init__(self, config):
        self.base = validate_url(config.get('tdp_url', ''), origin_only=True)
        self.key = config.get('tdp_key', '')
        self.secret = config.get('tdp_secret', '')
        if not self.key or not self.secret:
            raise AppError('请先在连接设置中配置 TDP 地址、API Key 和 Secret。')

    def call(self, operation, body):
        if operation not in self.PATHS:
            raise AppError('不支持该操作。')
        params = sign_query(self.key, self.secret, int(time.time()))
        result = request_json(self.base + self.PATHS[operation] + '?' + urllib.parse.urlencode(params), body)
        if not isinstance(result, dict) or result.get('response_code') != 0:
            code = result.get('response_code', 'unknown') if isinstance(result, dict) else 'unknown'
            if not isinstance(code, int):
                code = 'unknown'
            raise AppError('TDP 业务请求失败（代码 %s），请检查 API 开关、请求方状态、签名及两端时间。' % code, 502)
        data = result.get('data')
        if not isinstance(data, dict):
            raise AppError('TDP 返回的数据结构与当前适配器不兼容。', 502)
        return data

    def security(self, start, end):
        time_range(start, end)
        return self.call('security', {'time_from': start, 'time_to': end, 'assets_group': []})

    def hosts(self, start, end, keyword='', page=1, severity=None):
        time_range(start, end)
        if type(page) is not int or not 1 <= page <= 10000:
            raise AppError('页码不合法。')
        if severity is not None and (type(severity) is not int or severity not in range(5)):
            raise AppError('严重级别不合法。')
        if not isinstance(keyword, str) or len(keyword) > 200:
            raise AppError('查询关键词过长。')
        condition = {'time_from': start, 'time_to': end, 'threat_characters': []}
        if keyword:
            condition['fuzzy'] = {'keyword': keyword, 'fieldlist': ['threat.name', 'external_ip', 'machine', 'assets.name', 'data', 'machine_name']}
        if severity is not None:
            condition['severity'] = [severity]
        data = self.call('hosts', {'condition': condition,
                                'page': {'cur_page': page, 'page_size': 20, 'sort_by': 'severity', 'sort_flag': 'desc'}})
        if not isinstance(data.get('items'), list):
            raise AppError('告警主机响应缺少 items 列表。', 502)
        return data

    def logs(self, ip, start, end):
        time_range(start, end)
        from .evidence import canonical_target
        ip, kind = canonical_target(ip)
        if kind == 'ip':
            sql = "(machine = '{0}' OR net.src_ip = '{0}' OR net.dest_ip = '{0}' OR net.real_src_ip = '{0}')".format(ip)
        else:
            sql = "(data = '{0}' OR threat.ioc = '{0}')".format(ip)
        fields = ['id', 'time', 'machine', 'direction', 'data', 'threat', 'net.src_ip', 'net.dest_ip',
                  'net.real_src_ip', 'net.src_port', 'net.dest_port', 'net.type', 'assets', 'dest_assets', 'node_name', 'device_id', 'attacker', 'victim']
        data = self.call('logs', {'time_from': start, 'time_to': end, 'sql': sql,
                               'net_data_type': ['attack', 'risk', 'action'],
                               'columns': [{'label': field, 'value': field} for field in fields]})
        if not isinstance(data.get('data'), list):
            raise AppError('日志响应缺少 data 列表；日志调查接口要求 TDP 3.3.13 或兼容版本。', 502)
        return data
