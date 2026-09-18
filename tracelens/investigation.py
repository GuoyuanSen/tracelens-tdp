"""Deterministic evidence assessment. Never infer clean from missing evidence."""
import hashlib
import ipaddress
import json
from collections import Counter
from .tdp import AppError


def field(row, path, default=''):
    if path in row:
        return row[path]
    current = row
    for key in path.split('.'):
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def normalized(row):
    timestamp = field(row, 'time', 0)
    try:
        timestamp = int(timestamp)
    except (ValueError, TypeError):
        timestamp = 0
    severity = field(row, 'threat.severity', 0)
    try:
        severity = max(0, min(4, int(severity)))
    except (ValueError, TypeError):
        severity = 0
    fingerprint = hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return {'id': str(field(row, 'id') or fingerprint), 'time': timestamp,
            'name': str(field(row, 'threat.name') or '未命名事件'), 'severity': severity,
            'result': str(field(row, 'threat.result')), 'type': str(field(row, 'threat.type')),
            'phase': str(field(row, 'threat.phase')), 'direction': str(field(row, 'direction')),
            'machine': str(field(row, 'machine')), 'src_ip': str(field(row, 'net.src_ip')),
            'dest_ip': str(field(row, 'net.dest_ip')), 'indicator': str(field(row, 'threat.ioc') or field(row, 'data')),
            'connected': field(row, 'threat.is_connected') in (1, '1', True),
            'assets': field(row, 'assets', {}), 'dest_assets': field(row, 'dest_assets', {}), 'raw': row}


def analyze(ip, start, end, response):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise AppError('调查目标必须是 IP 地址。') from None
    rows = response.get('data', [])
    if not isinstance(rows, list):
        raise AppError('日志列表格式不正确。', 502)
    records = []
    discarded = 0
    for row in rows:
        if not isinstance(row, dict):
            discarded += 1
            continue
        event = normalized(row)
        addresses = [event['machine'], event['src_ip'], event['dest_ip'], str(field(row, 'net.real_src_ip'))]
        def same_ip(value):
            try:
                return str(ipaddress.ip_address(value)) == ip
            except ValueError:
                return False
        if not any(same_ip(value) for value in addresses) or not start <= event['time'] <= end:
            discarded += 1
            continue
        records.append(event)
    records.sort(key=lambda e: (e['time'], e['id']))
    # Same upstream id on separate sensors can differ; deduplicate by full record only.
    seen = set()
    evidence = []
    for event in records:
        fingerprint = hashlib.sha256(json.dumps(event['raw'], sort_keys=True).encode()).hexdigest()
        if fingerprint not in seen:
            seen.add(fingerprint)
            event['ref'] = 'E%03d' % (len(evidence) + 1)
            evidence.append(event)
    kept = evidence[:500]
    total = response.get('total')
    if type(total) is not int or total < 0:
        total = None
    partial = total is None or total > len(rows) or len(evidence) > 500 or discarded > 0
    groups = {
        'success': [e['ref'] for e in kept if e['result'] == 'success'],
        'remote': [e['ref'] for e in kept if e['direction'] == 'out' and e['connected'] and e['type'] in ('c2', 'rat', 'trojan', 'botnet')],
        'lateral': [e['ref'] for e in kept if e['direction'] == 'lateral'],
    }
    hypotheses = []
    for key, title, text in [
        ('success', '是否出现攻击成功记录？', 'TDP 将这些事件标记为攻击成功。需要结合终端证据确认实际影响。'),
        ('remote', '是否存在远控连接迹象？', '存在出站远控类事件且连接字段为真，建议核查进程、目的地址和业务用途。'),
        ('lateral', '是否出现内网渗透迹象？', '存在内网渗透方向的告警，尚不能仅凭方向确认横向移动成功。')]:
        refs = groups[key]
        hypotheses.append({'key': key, 'question': title, 'state': '有记录支持' if refs else '证据不足',
                           'finding': text if refs else '当前返回的记录未提供支持证据，不等于该行为不存在。', 'evidence': refs})
    gaps = ['网络告警不能替代终端取证；主机是否失陷仍需人工确认。', '仅覆盖所选时间范围和当前 API 请求方可见的数据。']
    if partial:
        gaps.append('结果覆盖不完整或总量未知：建议缩短时间窗口继续调查，不据此排除风险。')
    if discarded:
        gaps.append('%s 条记录因目标、时间或格式不匹配被排除。' % discarded)
    if not kept:
        gaps.append('未找到可用证据，请检查时间范围、IP、数据采集状态与查询权限。')
    counts = Counter(e['direction'] or 'unknown' for e in kept)
    return {'ip': ip, 'time_from': start, 'time_to': end, 'evidence': kept,
            'coverage': {'reported_total': total, 'returned': len(rows), 'retained': len(kept), 'partial': partial, 'discarded': discarded},
            'summary': {'events': len(kept), 'success': len(groups['success']), 'remote': len(groups['remote']),
                        'lateral': len(groups['lateral']), 'directions': dict(counts)},
            'assessment': '发现高关注线索，建议优先复核' if groups['success'] or groups['remote'] else '需要更多证据完成研判',
            'hypotheses': hypotheses, 'gaps': gaps,
            'next_steps': ['核实资产责任人与正常业务用途', '结合终端进程、登录和文件记录确认影响', '记录处置时间，并在后续时间窗口复查']}


def compare(before, after):
    old = {e['id'] for e in before['evidence']}
    return {'before_events': before['summary']['events'], 'after_events': after['summary']['events'],
            'new_ids': len({e['id'] for e in after['evidence']} - old),
            'statement': ('后续窗口仍有相关记录，需要继续复核。' if after['evidence'] else
                          '后续窗口未返回相关记录，不能据此确认风险已消除。'),
            'comparable': False,
            'note': '两个窗口长度、采集状态和返回覆盖可能不同；事件数不能直接作为处置有效性的证明。'}


def markdown_report(case):
    snap = case['snapshots'][-1]
    data = snap['analysis']
    lines = ['# TraceLens for TDP 调查报告', '',
             ('【合成数据演练】此报告不反映任何真实环境安全状态。' if case['source'].startswith('demo:') else '数据来源：用户配置的 TDP。'), '', '目标：%s' % case['ip'], '状态：%s' % case['status'],
             '查询范围（Unix 秒）：%s — %s' % (data['time_from'], data['time_to']), '',
             '## 规则辅助判断', '', data['assessment'], '此判断来自确定性规则，并非 AI 结论。', '']
    for item in data['hypotheses']:
        lines += ['### ' + item['question'], '', item['state'] + '：' + item['finding'],
                  '证据：' + (', '.join(item['evidence']) or '无'), '']
    lines += ['## 证据缺口', ''] + ['- ' + item for item in data['gaps']]
    lines += ['', '## 证据时间线', '']
    for e in data['evidence']:
        lines.append('- [%s] %s | %s | %s → %s | %s | 原始 ID: %s' %
                     (e['ref'], e['time'], e['name'].replace('\n', ' '), e['src_ip'], e['dest_ip'], e['result'], e['id']))
    lines += ['', '## 人工记录', '']
    for note in case['notes']:
        lines += ['- %s: %s' % (note['created_at'], note['text'])]
    if snap.get('ai'):
        lines += ['', '## AI 辅助分析（需人工复核）', '', snap['ai']['text']]
    return '\n'.join(lines) + '\n'
