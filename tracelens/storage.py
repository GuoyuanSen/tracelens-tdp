"""Local configuration and transactional case storage outside the source tree."""
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid
from .tdp import AppError, validate_url
from .evidence import enrich, enrich_case

FIELDS = ('tdp_url', 'tdp_key', 'tdp_secret', 'ai_url', 'ai_key', 'ai_model', 'mode')
SECRETS = ('tdp_key', 'tdp_secret', 'ai_key')


class Storage:
    def __init__(self, directory):
        self.directory = Path(directory).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.config_path = self.directory / 'config.json'
        self.db_path = self.directory / 'cases.sqlite3'
        self.lock = threading.RLock()
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, document TEXT NOT NULL, updated_at INTEGER NOT NULL)')
        os.chmod(self.db_path, 0o600)

    def connect(self):
        db = sqlite3.connect(str(self.db_path), timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        return db

    def config(self):
        with self.lock:
            data = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
            for key in FIELDS:
                env = os.environ.get('TRACELENS_' + key.upper())
                if env is not None:
                    data[key] = env
            return data

    def public_config(self):
        config = self.config()
        return {'mode': config.get('mode', 'live'), **{k: config.get(k, '') for k in FIELDS if k not in SECRETS and k != 'mode'},
                **{k + '_set': bool(config.get(k)) for k in SECRETS},
                'ready': config.get('mode') == 'demo' or all(config.get(k) for k in ('tdp_url', 'tdp_key', 'tdp_secret')),
                'ai_ready': config.get('mode') != 'demo' and all(config.get(k) for k in ('ai_url', 'ai_model')),
                'locked': [k for k in FIELDS if 'TRACELENS_' + k.upper() in os.environ]}

    def save_config(self, changes):
        with self.lock:
            if set(changes) - set(FIELDS) - {'clear_ai_key'}:
                raise AppError('包含不支持的配置项。')
            old = self.config()
            data = json.loads(self.config_path.read_text()) if self.config_path.exists() else {}
            for key in FIELDS:
                if key not in changes:
                    continue
                value = changes[key]
                if not isinstance(value, str) or len(value) > 4096:
                    raise AppError('配置项格式不合法。')
                if 'TRACELENS_' + key.upper() in os.environ:
                    if value and value != old.get(key):
                        raise AppError('该配置由环境变量管理，请在启动环境中修改。')
                    continue
                value = value.strip()
                if key == 'mode' and value not in ('live', 'demo'):
                    raise AppError('模式不合法。')
                if key in SECRETS and not value:
                    continue
                if key in ('tdp_url', 'ai_url') and value:
                    value = validate_url(value, origin_only=key == 'tdp_url')
                data[key] = value
            merged = {**old, **data}
            for key in FIELDS:
                if 'TRACELENS_' + key.upper() in os.environ:
                    merged[key] = old.get(key, '')
            if merged.get('tdp_url') != old.get('tdp_url') and old.get('tdp_key'):
                if not changes.get('tdp_key') or not changes.get('tdp_secret'):
                    raise AppError('更换 TDP 地址时，请重新填写该平台的 Key 和 Secret。')
            if merged.get('ai_url') != old.get('ai_url') and old.get('ai_key'):
                if not changes.get('ai_key') and not changes.get('clear_ai_key'):
                    raise AppError('更换模型服务地址时，请重新填写密钥或勾选清除旧密钥。')
            if changes.get('clear_ai_key'):
                if 'TRACELENS_AI_KEY' in os.environ:
                    raise AppError('模型密钥由环境变量管理。')
                data['ai_key'] = ''
            temp = self.config_path.with_suffix('.tmp')
            fd = os.open(str(temp), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as file:
                json.dump(data, file, ensure_ascii=False, indent=2)
            os.replace(temp, self.config_path)
            return self.public_config()

    def get(self, case_id):
        with self.connect() as db:
            row = db.execute('SELECT document FROM cases WHERE id=?', (case_id,)).fetchone()
        if not row:
            raise AppError('调查记录不存在。', 404)
        return enrich_case(json.loads(row[0]))

    def list(self):
        with self.connect() as db:
            rows = db.execute('SELECT document FROM cases ORDER BY updated_at DESC LIMIT 200').fetchall()
        return [{k: item[k] for k in ('id', 'ip', 'title', 'status', 'created_at', 'updated_at', 'source')}
                for item in (json.loads(row[0]) for row in rows)]

    def create(self, ip, source, analysis):
        now = int(time.time())
        enrich(analysis, source, now)
        case = {'id': uuid.uuid4().hex, 'ip': ip, 'title': ip + ' 主机调查', 'status': 'investigating',
                'source': source, 'created_at': now, 'updated_at': now, 'notes': [], 'links': [], 'remediations': [],
                'snapshots': [{'id': uuid.uuid4().hex, 'created_at': now, 'kind': 'initial', 'analysis': analysis}]}
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES (?,?,?)', (case['id'], json.dumps(case, ensure_ascii=False), now))
        return case

    def mutate(self, case_id, change):
        with self.lock, self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT document FROM cases WHERE id=?', (case_id,)).fetchone()
            if not row:
                raise AppError('调查记录不存在。', 404)
            case = enrich_case(json.loads(row[0]))
            change(case)
            case['updated_at'] = int(time.time())
            db.execute('UPDATE cases SET document=?, updated_at=? WHERE id=?',
                       (json.dumps(case, ensure_ascii=False), case['updated_at'], case_id))
            return case

    def create_linked(self, parent_id, snapshot_id, target, source, analysis, evidence_refs):
        with self.lock, self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT document FROM cases WHERE id=?', (parent_id,)).fetchone()
            if not row:
                raise AppError('来源调查不存在。', 404)
            parent = enrich_case(json.loads(row[0]))
            now = int(time.time())
            enrich(analysis, source, now)
            child_id = uuid.uuid4().hex
            link = {'case_id': parent_id, 'target': parent['ip'], 'snapshot_id': snapshot_id,
                    'evidence': evidence_refs, 'direction': 'parent'}
            child = {'id': child_id, 'ip': target, 'title': target + ' 关联调查', 'source': source,
                     'status': 'investigating', 'created_at': now, 'updated_at': now,
                     'notes': [], 'links': [link], 'remediations': [],
                     'snapshots': [{'id': uuid.uuid4().hex, 'created_at': now, 'kind': 'initial', 'analysis': analysis}]}
            parent['links'].append({'case_id': child_id, 'target': target, 'snapshot_id': snapshot_id,
                                    'evidence': evidence_refs, 'direction': 'child'})
            parent['updated_at'] = now
            db.execute('INSERT INTO cases VALUES (?,?,?)', (child_id, json.dumps(child, ensure_ascii=False), now))
            db.execute('UPDATE cases SET document=?,updated_at=? WHERE id=?', (json.dumps(parent, ensure_ascii=False), now, parent_id))
            return child
