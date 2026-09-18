"""Explicit synthetic training dataset using documentation-only IP ranges."""
import copy
from .tdp import AppError, time_range

DEMO_SOURCE = 'demo://tracelens/training-v1'
HOSTS = [
    {'ip': '192.0.2.10', 'name': '演练 · 财务终端', 'severity': 4},
    {'ip': '192.0.2.20', 'name': '演练 · 文件服务器', 'severity': 3},
    {'ip': '192.0.2.30', 'name': '演练 · 授权运维终端', 'severity': 1},
    {'ip': '192.0.2.40', 'name': '演练 · 证据不足主机', 'severity': 3},
]


class DemoClient:
    base = DEMO_SOURCE
    mode = 'demo'

    def __init__(self, anchor):
        self.anchor = anchor

    def dataset(self):
        # Anchor is stable for this process; queries genuinely filter timestamps.
        specs = [
            ('phishing', -7200, '192.0.2.10', '192.0.2.10', '198.51.100.50', 'out', 'phishing', 'unknown', 2, False, '可疑钓鱼站点访问', 'login-demo.example.com'),
            ('file', -6900, '192.0.2.10', '198.51.100.50', '192.0.2.10', 'in', 'file', 'unknown', 3, False, '可疑文件下载', 'invoice-demo.example.com'),
            ('remote', -6300, '192.0.2.10', '192.0.2.10', '203.0.113.40', 'out', 'c2', 'success', 4, True, '远控心跳连接', 'c2-demo.example.com'),
            ('lateral', -5400, '192.0.2.10', '192.0.2.10', '192.0.2.20', 'lateral', 'exploit', 'success', 4, False, '横向访问异常', '192.0.2.20'),
            ('server', -4800, '192.0.2.20', '192.0.2.20', '203.0.113.40', 'out', 'c2', 'unknown', 3, False, '服务器可疑外连尝试', 'c2-demo.example.com'),
            ('retry', -3600, '192.0.2.10', '192.0.2.10', '203.0.113.40', 'out', 'c2', 'success', 4, True, '远控连接重复出现', 'c2-demo.example.com'),
            ('admin', -2700, '192.0.2.30', '192.0.2.30', '192.0.2.20', 'lateral', 'recon', 'failed', 1, False, '管理端口扫描尝试', '192.0.2.20'),
        ]
        names = {host['ip']: host['name'] for host in HOSTS}
        rows=[]
        for identifier, offset, machine, src, dst, direction, kind, result, severity, connected, name, indicator in specs:
            rows.append({'id': 'synthetic-' + identifier, 'time': self.anchor + offset, 'machine': machine,
                         'direction': direction, 'data': indicator, 'synthetic': True,
                         'threat': {'name': '[合成演练] ' + name, 'type': kind, 'result': result,
                                    'severity': severity, 'is_connected': int(connected), 'ioc': indicator, 'suuid': 'synthetic-rule-' + kind},
                         'net': {'src_ip': src, 'dest_ip': dst, 'src_port': 48000, 'dest_port': 443, 'type': 'tcp'},
                         'assets': {'name': [names.get(src, '演练外部地址')], 'group_name': '合成演练环境'},
                         'dest_assets': {'name': [names.get(dst, '演练外部地址')], 'group_name': '合成演练环境'}})
        for row in rows:
            row['device_id'] = 'synthetic-sensor-01'
            row['node_name'] = '演练节点'
            if row['direction'] == 'lateral':
                row['attacker'] = row['net']['src_ip']
                row['victim'] = row['net']['dest_ip']
        for index in range(12):
            heartbeat = copy.deepcopy(rows[2])
            heartbeat['id'] = 'synthetic-heartbeat-%02d' % index
            heartbeat['time'] = self.anchor - 6200 + index * 30
            rows.append(heartbeat)
        operations = copy.deepcopy(rows[6])
        operations['id'] = 'synthetic-approved-maintenance'
        operations['time'] = self.anchor - 2600
        operations['threat']['name'] = '[合成演练] 管理端口扫描尝试'
        operations['training_context'] = {'approved_change': 'EXERCISE-CHANGE-001', 'purpose': '授权运维资产扫描',
                                         'warning': '只适用于这个合成案例；仍需人工核对范围和时间，不自动排除其他告警。'}
        rows.append(operations)
        rows.append({'id': 'synthetic-incomplete', 'time': self.anchor - 1800, 'machine': '192.0.2.40',
                     'synthetic': True, 'node_name': '演练采集缺口节点', 'direction': 'in',
                     'threat': {'name': '[合成演练] 可疑访问，结果未知', 'type': 'exploit', 'result': 'unknown', 'severity': 3},
                     'net': {'src_ip': '198.51.100.80', 'dest_ip': '192.0.2.40'}, 'data': 'unknown-demo.example.com'})
        return rows

    def logs(self, ip, start, end):
        time_range(start,end)
        from .evidence import canonical_target, target_matches
        from .investigation import normalized
        target, kind = canonical_target(ip)
        rows=[copy.deepcopy(row) for row in self.dataset() if start<=row['time']<=end and target_matches(normalized(row),target,kind)]
        # Deliberately model an incomplete collector response in the uncertainty exercise.
        total = len(rows) + 7 if target == '192.0.2.40' and rows else len(rows)
        return {'data':rows,'total':total}

    def hosts(self,start,end,keyword='',page=1,severity=None):
        time_range(start,end)
        if type(page) is not int or page<1:
            raise AppError('页码不合法。')
        rows=[]
        for host in HOSTS:
            events=self.logs(host['ip'],start,end)['data']
            if not events:
                continue
            latest=max(events,key=lambda row:row['time'])
            item={'machine':host['ip'],'asset_name':host['name'],'max_severity':host['severity'],
                  'threat_name':latest['threat']['name'],'last_occ_time':latest['time'],
                  'direction':latest['direction'],'host_disposal_status':1}
            if keyword and keyword.lower() not in str(item).lower():
                continue
            if severity is not None and severity!=host['severity']:
                continue
            rows.append(item)
        return {'items':rows[(page-1)*20:page*20], 'page':{'total_num':len(rows),'cur_page':page,'page_size':20}}

    def security(self,start,end):
        hosts=self.hosts(start,end)['items']
        return {'level':'CRITICAL' if hosts else 'UNKNOWN','level_desc':'演练态势' if hosts else '无演练记录',
                'compromised_host_count':1 if hosts else 0,'unhandled_host_count':len(hosts),'block_host_count':0}
