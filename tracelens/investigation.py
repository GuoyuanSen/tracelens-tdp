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
    def address(value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return str(value)
    fingerprint = hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return {'id': str(field(row, 'id') or fingerprint), 'time': timestamp,
            'name': str(field(row, 'threat.name') or '未命名事件'), 'severity': severity,
            'result': str(field(row, 'threat.result')), 'type': str(field(row, 'threat.type')),
            'phase': str(field(row, 'threat.phase')), 'direction': str(field(row, 'direction')),
            'machine': str(field(row, 'machine')), 'src_ip': address(field(row, 'net.src_ip')),
            'dest_ip': address(field(row, 'net.dest_ip')), 'indicator': str(field(row, 'threat.ioc') or field(row, 'data')),
            'connected': field(row, 'threat.is_connected') in (1, '1', True),
            'assets': field(row, 'assets', {}), 'dest_assets': field(row, 'dest_assets', {}), 'raw': row}


def analyze(ip, start, end, response):
    from .evidence import canonical_target, target_matches, enrich
    ip, kind = canonical_target(ip)
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
        if not target_matches(event, ip, kind) or not start <= event['time'] <= end:
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
    partial = total is None or total != len(rows) or len(evidence) > 500 or discarded > 0
    gaps = ['网络告警不能替代终端取证；主机是否失陷仍需人工确认。', '仅覆盖所选时间范围和当前 API 请求方可见的数据。']
    if partial:
        gaps.append('结果覆盖不完整或总量未知：建议缩短时间窗口继续调查，不据此排除风险。')
    if discarded:
        gaps.append('%s 条记录因目标、时间或格式不匹配被排除。' % discarded)
    if not kept:
        gaps.append('未找到可用证据，请检查时间范围、IP、数据采集状态与查询权限。')
    counts = Counter(e['direction'] or 'unknown' for e in kept)
    return enrich({'ip': ip, 'time_from': start, 'time_to': end, 'evidence': kept,
            'coverage': {'reported_total': total, 'returned': len(rows), 'retained': len(kept), 'partial': partial, 'discarded': discarded, 'duplicate_rows': len(records)-len(evidence)},
            'summary': {'events': len(kept), 'directions': dict(counts)}, 'gaps': gaps,
            'next_steps': ['核实资产责任人与正常业务用途', '结合终端进程、登录和文件记录确认影响', '记录处置时间，并在后续时间窗口复查']})


def compare(before, after):
    old = {e['id'] for e in before['evidence']}
    return {'before_events': before['summary']['events'], 'after_events': after['summary']['events'],
            'new_ids': len({e['id'] for e in after['evidence']} - old),
            'statement': ('后续窗口仍有相关记录，需要继续复核。' if after['evidence'] else
                          '后续窗口未返回相关记录，不能据此确认风险已消除。'),
            'comparable': False,
            'note': '两个窗口长度、采集状态和返回覆盖可能不同；事件数不能直接作为处置有效性的证明。'}


def markdown_text(value):
    """Do not let untrusted log fields create active Markdown/HTML in an export."""
    import html
    import re
    return re.sub(r'([\\`*{}\[\]()!#|])', r'\\\1', html.escape(str(value), quote=False))


def markdown_report(case):
    snap = case['snapshots'][-1]
    data = snap['analysis']
    lines = ['# TraceLens for TDP 调查报告', '',
             ('【合成数据演练】此报告不反映任何真实环境安全状态。' if case['source'].startswith('demo:') else '数据来源：用户配置的 TDP。'), '', '目标：%s' % case['ip'], '状态：%s' % case['status'], '来源平台：%s' % case['source'], '快照 ID：%s' % snap['id'],
             '采集时间：%s' % data.get('collected_at', snap['created_at']),
             '覆盖信息：%s' % json.dumps(data['coverage'], ensure_ascii=False),
             '查询范围（Unix 秒）：%s — %s' % (data['time_from'], data['time_to']), '',
             '## 规则辅助判断', '', data['assessment'], '此判断来自确定性规则，并非 AI 结论。', '']
    for item in data['hypotheses']:
        lines += ['### ' + item['question'], '', item['state'] + '：' + item['finding'],
                  '证据：' + (', '.join(item['evidence']) or '无'), '']
    lines += ['## 证据缺口', ''] + ['- ' + item for item in data['gaps']]
    lines += ['', '## 告警归并', '']
    for group in data.get('groups', []):
        lines.append('- %s | %s | %s 条 | %s — %s | %s' % (group['id'], markdown_text(group['name']), group['count'], group['first_seen'], group['last_seen'], ', '.join(group['evidence'])))
    lines += ['', '## 证据时间线', '']
    for e in data['evidence']:
        lines.append('- [%s] %s | %s | %s → %s | %s | 原始 ID: %s' %
                     (e['ref'], e['time'], markdown_text(e['name'].replace('\n', ' ')), markdown_text(e['src_ip']), markdown_text(e['dest_ip']), markdown_text(e['result']), markdown_text(e['id'])))
        provenance = e.get('provenance', {})
        lines.append('  角色：%s；来源：%s；节点：%s；采集时间：%s；SHA-256：%s' % (e.get('role', {}).get('label', '未知'), markdown_text(provenance.get('source', '')), markdown_text(provenance.get('node', '')), provenance.get('collected_at'), provenance.get('sha256', '')))
    lines += ['', '## 关联调查', '', markdown_text(json.dumps(case.get('links', []), ensure_ascii=False)), '', '## 处置记录（用户声明，工具未执行）', '', markdown_text(json.dumps(case.get('remediations', []), ensure_ascii=False))]
    if snap.get('remediation_comparison'):
        lines += ['', '## 处置后复查', '', markdown_text(json.dumps(snap['remediation_comparison'], ensure_ascii=False, indent=2))]
    lines += ['', '## 人工记录', '']
    for note in case['notes']:
        lines += ['- %s: %s' % (note['created_at'], markdown_text(note['text']))]
    if snap.get('ai'):
        lines += ['', '## AI 辅助分析（需人工复核）', '', markdown_text(snap['ai']['text'])]
    return '\n'.join(lines) + '\n'
