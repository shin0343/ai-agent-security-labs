"""Multi-source evidence ingestion. IP observations must not imply process attribution."""
from pathlib import Path
from dataclasses import dataclass, asdict
import json

FILES = ('conn.log','dns.log','http.log','ssl.log','suricata.ndjson','windows-events.ndjson','agent-actions.ndjson')
@dataclass(frozen=True)
class Event:
    source: str
    line: int
    payload: dict
    @property
    def ref(self):
        return f'{self.source}:{self.line}'

@dataclass
class Finding:
    agent: str
    score: float
    disposition: str
    evidence: list[str]
    rationale: str
    limits: str
    def json(self):
        return asdict(self)

def ingest(root: Path):
    root = Path(root)
    items = []
    for filename in FILES:
        file = root / filename
        if not file.is_file():
            raise ValueError(f'Missing required source: {filename}')
        for n, raw in enumerate(file.read_text(encoding='utf-8').splitlines(), 1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f'Invalid JSON at {filename}:{n}') from exc
            if not isinstance(obj, dict):
                raise ValueError(f'Expected JSON object at {filename}:{n}')
            items.append(Event(filename,n,obj))
    return items

def inspect_ref(root: Path, ref: str):
    filename, sep, line = ref.partition(':')
    if not sep or filename not in FILES or not line.isascii() or not line.isdigit() or int(line) < 1:
        raise ValueError('Invalid evidence reference')
    events = [e for e in ingest(root) if e.ref == ref]
    if not events:
        raise ValueError('Evidence reference not found')
    return events[0].payload

def analyze(events):
    def matching(source, predicate):
        return [e for e in events if e.source == source and predicate(e.payload)]
    data_action = matching('agent-actions.ndjson',lambda d: d.get('agent') == 'data' and d.get('action') == 'publish_external' and d.get('approved') is False)
    post = matching('http.log',lambda d:d.get('method')=='POST' and d.get('id.resp_h') == '203.0.113.77')
    alert = matching('suricata.ndjson',lambda d:d.get('event_type')=='alert' and d.get('dest_ip')=='203.0.113.77')
    score_data = round((0.55 if data_action else 0)+(0.25 if post else 0)+(0.20 if alert else 0), 2)
    hd_action = matching('agent-actions.ndjson',lambda d:d.get('agent')=='helpdesk' and d.get('action')=='winrm_login' and d.get('resource') not in d.get('approved_scope',[]))
    failed_login = matching('windows-events.ndjson',lambda d:d.get('EventID') == 4625 and d.get('EventData',{}).get('TargetHost')=='192.0.2.44')
    score_hd=round((0.70 if hd_action else 0)+(0.20 if failed_login else 0),2)
    build=matching('agent-actions.ndjson',lambda d:d.get('agent')=='build')
    docs=matching('ssl.log',lambda d:d.get('server_name')=='docs.demo.invalid')
    return [
        Finding('build',0.0,'LOW',[e.ref for e in build], 'Synthetic build action within declared scope', 'No proof that all activity is benign'),
        Finding('data',score_data,'REVIEW' if score_data >= .70 else 'LOW', [e.ref for e in data_action+post+alert], 'Unapproved publish request alongside outbound POST and IDS alert', 'The shared host IP does not establish process/agent ownership of the network flow or successful exfiltration'),
        Finding('helpdesk',score_hd,'REVIEW' if score_hd >= .70 else 'LOW',[e.ref for e in hd_action+failed_login], 'Attempted WinRM login outside one-host approved scope', 'Login failure is not evidence of successful remote access'),
        Finding('docs',0.30 if docs else 0.0,'UNKNOWN',[e.ref for e in docs], 'External TLS/SNI observed; authorization and payload unknown', 'TLS metadata alone cannot prove intent or data loss'),
    ]

def hunt(root: Path):
    return analyze(ingest(root))
