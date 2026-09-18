"""Role-aware, auditable interpretation of retained evidence."""
import hashlib
import ipaddress
import json
from collections import Counter
from urllib.parse import urlsplit
from .tdp import AppError


def canonical_target(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 253:
        raise AppError('请输入合法的 IP 或完整域名。')
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value)), 'ip'
    except ValueError:
        pass
    import re
    try:
        domain = value.rstrip('.').encode('idna').decode().lower()
    except UnicodeError:
        raise AppError('域名格式不正确。') from None
    if len(domain) > 253:
        raise AppError('域名长度超出限制。')
    labels = domain.split('.')
    if len(labels) < 2 or not any(c.isalpha() for c in labels[-1]) or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels):
        raise AppError('请输入 IP 或域名，不包含协议、路径或查询表达式。')
    return domain, 'domain'


def same_address(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def target_matches(event, target, kind):
    from .investigation import field
    raw = event['raw']
    if kind == 'ip':
        return any(same_address(target, v) for v in [event['machine'], event['src_ip'], event['dest_ip'], field(raw, 'net.real_src_ip')])
    values = [event['indicator'], field(raw, 'data'), field(raw, 'threat.ioc')]
    return any(isinstance(v, str) and v.lower().rstrip('.') == target for v in values)


def event_roles(event, target, kind):
    from .investigation import field
    if kind != 'ip':
        return {'network': 'indicator', 'security': 'unknown', 'label': '情报关联对象', 'basis': '域名命中，不代表主机身份'}
    raw = event['raw']
    src = same_address(event['src_ip'], target) or same_address(field(raw, 'net.real_src_ip'), target)
    dst = same_address(event['dest_ip'], target)
    network = 'both' if src and dst else 'source' if src else 'destination' if dst else 'associated'
    attacker = same_address(field(raw, 'attacker'), target)
    victim = same_address(field(raw, 'victim'), target)
    security = 'conflict' if attacker and victim else 'attacker' if attacker else 'victim' if victim else 'unknown'
    labels = {'source': '通信源', 'destination': '通信目的', 'both': '源/目的重合', 'associated': '仅告警关联'}
    security_labels = {'attacker': '原始字段标记攻击者', 'victim': '原始字段标记受害者', 'conflict': '角色字段冲突', 'unknown': '攻击角色未确认'}
    return {'network': network, 'security': security,
            'label': labels[network] + ' · ' + security_labels[security],
            'basis': '网络角色来自 src_ip / real_src_ip / dest_ip；攻击角色只采纳明确的 attacker / victim 字段，不由方向推断。'}


def group_key(e, include_peer=True):
    from .investigation import field
    raw = e['raw']
    # Result and sensor boundaries are retained; different evidence must not silently merge.
    signature = str(field(raw, 'threat.suuid') or e['name'])
    values = [signature, e['type'], e['direction'], e['result'], e.get('role', {}).get('network'), e.get('role', {}).get('security'),
              str(field(raw, 'device_id')), str(field(raw, 'node_name'))]
    if include_peer:
        values += [e['src_ip'], e['dest_ip'], e['indicator']]
    return tuple(values)


def enrich(analysis, source='', collected_at=None, legacy=False):
    from .investigation import field
    target, kind = canonical_target(analysis['ip'])
    events = analysis['evidence']
    groups = {}
    for e in events:
        e['role'] = event_roles(e, target, kind)
        raw_hash = hashlib.sha256(json.dumps(e['raw'], sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        e['provenance'] = {'source': source, 'node': str(field(e['raw'], 'node_name') or field(e['raw'], 'device_id') or '未返回'),
                           'original_id': e['id'], 'original_id_returned': bool(field(e['raw'], 'id')),
                           'collected_at': collected_at, 'time_basis': '历史快照保存时间（非精确请求时间）' if legacy else '查询完成时间',
                           'sha256': raw_hash, 'hash_format': 'sorted UTF-8 JSON, compact separators; not a signed chain of custody',
                           'time_from': analysis['time_from'], 'time_to': analysis['time_to']}
        key = group_key(e)
        if key not in groups:
            groups[key] = {'id': 'G%03d' % (len(groups)+1), 'name': e['name'], 'type': e['type'],
                           'direction': e['direction'], 'result': e['result'], 'role': e['role']['label'],
                           'src_ip': e['src_ip'], 'dest_ip': e['dest_ip'], 'count': 0,
                           'first_seen': e['time'], 'last_seen': e['time'], 'evidence': []}
        group = groups[key]
        group['count'] += 1
        group['first_seen'] = min(group['first_seen'], e['time'])
        group['last_seen'] = max(group['last_seen'], e['time'])
        group['evidence'].append(e['ref'])
    analysis['target_kind'] = kind
    analysis['groups'] = list(groups.values())
    analysis['role_counts'] = dict(Counter(e['role']['network'] for e in events))
    success = [e['ref'] for e in events if e['result']=='success' and e['role']['security']=='victim']
    remote = [e['ref'] for e in events if e['direction']=='out' and e['connected'] and
              e['type'] in ('c2','rat','trojan','botnet') and e['role']['network']=='source' and e['role']['security']!='conflict']
    lateral = [e['ref'] for e in events if e['direction']=='lateral' and e['role']['network']=='source']
    analysis['summary'].update({'success': len(success), 'remote': len(remote), 'lateral': len(lateral),
                                'related_success': sum(e['result']=='success' for e in events), 'groups': len(groups)})
    definitions = [
        ('success', '目标是否有被攻击成功的字段证据？', success,
         '记录将目标明确标记为受害者，且结果为成功。仍需终端证据确认实际影响。',
         [e['ref'] for e in events if e['role']['security']=='victim' and e['result']=='failed']),
        ('remote', '目标是否主动连接远控类地址？', remote,
         '目标位于通信源，远控类出站记录的连接字段为真。需要核实进程和业务背景。', []),
        ('lateral', '目标是否发起内网渗透类通信？', lateral,
         '目标为内网渗透方向的通信源；不能仅凭该方向断言横向移动成功。', [])]
    analysis['hypotheses'] = [{'key': key, 'question': title, 'state': '有记录支持' if refs else '证据不足',
        'finding': finding if refs else '当前证据不支持确认该判断；角色缺失或未命中不能解释为安全。',
        'evidence': refs, 'opposing_evidence': opposing,
        'opposing_note': '失败记录只涉及对应事件，不能否定其他事件成功。' if opposing else '当前未找到直接反证，不代表假设成立。',
        'missing': ['终端执行证据', '资产用途与业务背景', '完整采集与时间覆盖'],
        'next_step': '核对引用记录中的角色和结果字段，再结合终端与业务核查。'}
        for key,title,refs,finding,opposing in definitions]
    analysis['assessment'] = '目标存在需要优先核实的线索' if success or remote else '现有证据不足以确认目标失陷'
    if kind=='domain':
        analysis['assessment'] = '域名命中是关联线索，不能据此判断具体主机失陷'
    analysis['coverage']['scope_note'] = '仅针对该查询、时间窗口与请求方可见数据；返回完整也不代表环境采集完整。'
    analysis['coverage']['duplicate_rows'] = analysis['coverage'].get('duplicate_rows', None if legacy else 0)
    analysis['analysis_version'] = 2
    analysis['source'] = source
    analysis['collected_at'] = collected_at
    if kind == 'domain':
        analysis['next_steps'] = ['从关联 IP 建立主机调查，明确通信发起方', '核实域名业务用途与 IOC 时效', '补充对应主机证据，避免由域名命中推断主机失陷']
    analysis['related_targets'] = related_targets(events, target)
    return analysis


def related_targets(events, target):
    targets = {}
    for e in events:
        for value in (e['src_ip'], e['dest_ip'], e['indicator']):
            if not value:
                continue
            try:
                candidate, kind = canonical_target(value)
            except AppError:
                # URL host extraction is for explicit pivot suggestions only; logs queries stay exact-match.
                try:
                    parsed = urlsplit(value)
                    candidate, kind = canonical_target(parsed.hostname or '')
                except (AppError, ValueError):
                    continue
            if candidate==target:
                continue
            item = targets.setdefault(candidate, {'target':candidate,'kind':kind,'evidence':[]})
            if e['ref'] not in item['evidence']:
                item['evidence'].append(e['ref'])
    return sorted(targets.values(), key=lambda item: (-len(item['evidence']), item['target']))


def enrich_case(case):
    case.setdefault('remediations', [])
    case.setdefault('links', [])
    for snap in case['snapshots']:
        a = snap['analysis']
        if a.get('analysis_version') != 2:
            enrich(a, case['source'], snap['created_at'], legacy=True)
            if snap.get('ai'):
                snap['ai'].setdefault('warnings', []).append('此分析使用旧版角色规则生成，需要重新核查。')
    return case


def remediation_comparison(before, after, remediation):
    baseline = [e for e in before['evidence'] if e['time'] < remediation['performed_at']]
    post = [e for e in after['evidence'] if e['time'] >= remediation['performed_at']]
    old_behaviors = {group_key(e, False) for e in baseline}
    old_routes = {group_key(e, True) for e in baseline}
    repeated = [e['ref'] for e in post if group_key(e,True) in old_routes]
    changed = [e['ref'] for e in post if group_key(e,False) in old_behaviors and group_key(e,True) not in old_routes]
    return {'remediation_id': remediation['id'], 'performed_at': remediation['performed_at'],
            'action': remediation['action'], 'baseline_evidence': len(baseline), 'post_evidence': len(post),
            'repeated_evidence': repeated, 'changed_peer_evidence': changed,
            'baseline_missing': not bool(baseline),
            'coverage_partial': before['coverage']['partial'] or after['coverage']['partial'],
            'statement': '处置后仍有同类行为或新记录，需要继续核实。' if post else '处置后未返回相关记录，不能确认风险已消除。',
            'note': '按记录类型、规则、方向、角色、结果及节点进行同类比较；对端改变是排查线索，不证明攻击迁移。'}
