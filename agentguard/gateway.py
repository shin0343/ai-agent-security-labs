"""Pre-execution enforcement for a small allowlisted simulated tool surface.
No arbitrary filesystem, subprocess, socket, or external publish capability exists.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, os, secrets, threading
from .audit import Audit, canonical

TOOL_SCHEMAS={
    'read_report':{'report_id': {'quarterly-synthetic'}},
    'publish_external':{'artifact_id':{'quarterly-synthetic'},'destination':{'demo-internal-outbox'}},
    'read_secret':{'name':{'production-env'}},
}
MODES=('deny','approve','monitor')

def validate(tool,args):
    schema=TOOL_SCHEMAS.get(tool)
    return bool(schema is not None and isinstance(args,dict) and args.keys()==schema.keys() and all(type(args[k]) is str and args[k] in accepted for k,accepted in schema.items()))

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

class Gateway:
    def __init__(self,run_dir):
        self.root=Path(run_dir); self.root.mkdir(parents=True,exist_ok=True)
        self.audit=Audit(self.root)
        self.state_path=self.root/'requests.json'
        self.lock=threading.RLock()
        try:self.requests=json.loads(self.state_path.read_text(encoding='utf-8')) if self.state_path.exists() else {}
        except (ValueError,TypeError) as ex:raise ValueError('Invalid request state') from ex
        if not isinstance(self.requests,dict): raise ValueError('Invalid request state')
    def _save(self):
        temp=self.root/('.state-'+secrets.token_hex(6))
        fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(self.requests,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.state_path)
    def _event(self,req,status):
        self.audit.append({'time':now(),'id':req['id'],'tool':req['tool'],'status':status,'mode':req['mode'],'args_sha256':hashlib.sha256(canonical(req['args'])).hexdigest()})
    def _execute_fake(self,req):
        if req['tool']=='read_report':return {'kind':'synthetic_report','summary':'Synthetic quarterly report: 3 internal test items. No secrets.'}
        if req['tool']=='publish_external':
            dest=self.root/'outbox';dest.mkdir(exist_ok=True)
            path=dest/(req['id']+'.json')
            # The external action is simulated only. Never opens a network connection.
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:
                json.dump({'simulated':True,'artifact':req['args']['artifact_id'],'destination':'local-outbox','request_id':req['id']},f)
            return {'kind':'simulated_publish','local_receipt':str(path.relative_to(self.root))}
        raise AssertionError('Unreachable forbidden tool')
    def request(self,tool,args,mode='deny'):
        if mode not in MODES:raise ValueError('Unknown policy mode')
        if not isinstance(tool,str): raise ValueError('Tool name must be a string')
        with self.lock:
            req={'id':secrets.token_hex(12),'time':now(),'tool':tool[:100], 'args':args if isinstance(args,dict) else {},'mode':mode,'status':'NEW'}
            if not validate(tool,args) or tool=='read_secret':status='BLOCK'
            elif tool=='read_report':status='ALLOW'
            elif mode=='deny':status='BLOCK'
            elif mode=='approve':status='PENDING'
            else:status='MONITORED'
            req['status']=status
            if status in ('ALLOW','MONITORED'):req['result']=self._execute_fake(req)
            self.requests[req['id']]=req;self._save();self._event(req,status)
            return self.public(req)
    def decide(self,request_id,approve):
        if type(approve) is not bool: raise ValueError('Approval must be boolean')
        with self.lock:
            req=self.requests.get(request_id)
            if not req or req['status']!='PENDING':raise ValueError('Request not pending (unknown or already decided)')
            if not validate(req['tool'],req['args']) or req['tool']!='publish_external':
                # Do not trust persisted approvals or the caller.
                req['status']='BLOCK'
            else:req['status']='APPROVED' if approve else 'REJECTED'
            if req['status']=='APPROVED':req['result']=self._execute_fake(req)
            self._save();self._event(req,req['status'])
            return self.public(req)
    @staticmethod
    def public(req):
        # Exclude untrusted argument bodies (and potential secrets) from UI and case exports.
        return {k:req[k] for k in ('id','time','tool','mode','status')}
    def summary(self):
        with self.lock:
            return {'requests':[self.public(r) for r in reversed(list(self.requests.values()))], 'audit_count':len(self.audit.read()),'audit_valid':self.audit.verify()}
