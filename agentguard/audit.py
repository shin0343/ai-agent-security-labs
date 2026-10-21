"""HMAC-chained local audit records; key material never included in exports."""
from pathlib import Path
import hashlib,hmac,json,os,secrets

def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

class Audit:
    def __init__(self, run_dir):
        self.root = Path(run_dir); self.root.mkdir(parents=True,exist_ok=True)
        self.path=self.root/'audit.jsonl'; self.key_path=self.root/'.audit-key'
        if not self.key_path.exists():
            fd=os.open(self.key_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as f: f.write(secrets.token_bytes(32))
        self.key=self.key_path.read_bytes()
        if len(self.key)!=32: raise ValueError('Invalid audit key')
        if self.path.exists() and not self.verify():
            raise ValueError('Audit verification failed; refusing to append')
    def read(self):
        if not self.path.exists():return []
        return [json.loads(s) for s in self.path.read_text(encoding='utf-8').splitlines() if s.strip()]
    def verify(self):
        prev='0'*64
        try:
            for n,entry in enumerate(self.read(),1):
                if entry.get('seq')!=n or entry.get('prev')!=prev: return False
                payload={k:v for k,v in entry.items() if k!='mac'}
                digest=hmac.new(self.key,canonical(payload),hashlib.sha256).hexdigest()
                if not hmac.compare_digest(entry.get('mac',''),digest):return False
                prev=digest
            return True
        except (ValueError,TypeError,KeyError,UnicodeError):return False
    def append(self, payload):
        entries=self.read(); prev=entries[-1]['mac'] if entries else '0'*64
        record={'seq':len(entries)+1,'prev':prev,'event':payload}
        record['mac']=hmac.new(self.key,canonical(record),hashlib.sha256).hexdigest()
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        with os.fdopen(fd,'a',encoding='utf-8') as f:
            f.write(json.dumps(record,ensure_ascii=False,sort_keys=True)+'\n'); f.flush(); os.fsync(f.fileno())
        return record
