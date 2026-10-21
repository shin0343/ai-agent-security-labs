"""Local-only lab dashboard. Not an authenticated production SOC."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
from html import escape
import json, secrets
from .gateway import Gateway,TOOL_SCHEMAS,MODES
from .hunt import hunt

HTML='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentGuard / Local Security Control Center</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101316;color:#e6e8e7;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{padding:26px 5vw;border-bottom:1px solid #353b3e;display:flex;justify-content:space-between;align-items:center;gap:24px}.eyebrow{text-transform:uppercase;letter-spacing:.15em;color:#a6b4b5;font-size:11px}h1{font-size:26px;letter-spacing:-.05em;margin:.2em 0}main{max-width:1300px;margin:0 auto;padding:30px 5vw 80px}h2{font-size:16px;margin:0 0 18px}.minor{color:#aeb8b8;font-size:13px}.split{display:grid;grid-template-columns:1fr 1fr;gap:20px}section{background:#191e22;border:1px solid #353c40;border-radius:8px;padding:24px;margin:0 0 20px}section.full{margin-top:5px}.summary{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}.chip{border:1px solid #414a50;padding:10px 14px;border-radius:5px;font-size:13px}.chip b{display:block;font-size:22px}.finding{border-top:1px solid #353c40;padding:16px 0}.finding strong{font-size:16px}.tag{font:11px ui-monospace,monospace;border:1px solid #6c8085;color:#d5e8ed;border-radius:3px;padding:3px 6px;margin-left:10px}.tag.review{color:#f1c6ad;border-color:#a86a54}.tag.unknown{color:#f1dda7;border-color:#85714a}button,select{background:#263238;color:#f1f5f4;border:1px solid #65787d;border-radius:4px;padding:10px 12px;font:inherit;cursor:pointer}button:hover{background:#384951}button:disabled{opacity:.4;cursor:default}select{width:100%;margin:6px 0 14px}button.primary{background:#d1dcd6;color:#14201d;font-weight:650}.inline{display:flex;gap:8px;align-items:center}.row{padding:12px 0;border-top:1px solid #353c40;display:flex;gap:8px;justify-content:space-between;align-items:center;flex-wrap:wrap}.status{font:12px ui-monospace,monospace;color:#aac5ba}.refs{font:12px/1.8 ui-monospace,monospace;color:#bfcbd4;word-break:break-all}.err{color:#f3b49a}pre{white-space:pre-wrap;word-break:break-all}footer{color:#9ca5a7;margin-top:30px}a{color:#b1cfdf}@media(max-width:750px){.split{grid-template-columns:1fr}header{display:block}}
</style></head><body><header><div><div class="eyebrow">RESEARCH PROJECT · EDUCATIONAL DATA</div><h1>AgentGuard <span class="minor">/ Local Security Control Center</span></h1></div><div class="minor">OFFLINE EVIDENCE · HUMAN-GATED TOOLS · AUDITABLE CASES</div></header><main><div class="summary"><div class="chip">DATASET<b>4 agents</b></div><div class="chip">DETECTIONS<b id="det">—</b></div><div class="chip">TOOL ACTIONS<b id="req">—</b></div><div class="chip">AUDIT CHAIN<b id="chain">—</b></div></div><div class="split"><section><h2>01 / Threat findings</h2><div class="minor">Evidence refs point to exact synthetic source lines. Suspicion is not proof of malicious intent.</div><div id="findings"></div></section><section><h2>02 / Pre-execution policy gate</h2><p class="minor">Requests use exact allowlisted arguments. "External publish" writes only a local JSON receipt — no network.</p><label for="mode" class="eyebrow">Policy mode</label><select id="mode"><option value="deny">Deny — fail closed</option><option value="approve">Approve — human once</option><option value="monitor">Monitor — simulated write + audit</option></select><div class="inline"><button class="primary" id="read">Read report</button><button id="publish">Publish (simulated)</button><button id="secret">Secret (blocked)</button></div><p id="result" class="minor" role="status" aria-live="polite"></p><h2 style="margin-top:30px">Pending approvals</h2><div id="pending" class="minor"></div></section></div><section class="full"><h2>03 / Case & audit timeline</h2><p class="minor">Export via CLI: <code>python3 -m agentguard export-case</code> then open <code>run/reports/vigil_case_draft.md</code>. Manual Vigil entry only.</p><div id="history"></div></section><footer>Localhost only. No live IDS, no external publishing, no SOC production claims. Sources and limitations documented in repository.</footer></main>
<script>
const token=__TOKEN__; const $=id=>document.getElementById(id); const el=(tag,txt,cls)=>{const e=document.createElement(tag);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e};
async function api(path,body){const opts=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Lab-Token':token},body:JSON.stringify(body)};const res=await fetch(path,opts);const j=await res.json();if(!res.ok)throw Error(j.error||'Request failed');return j}
async function refresh(){try{const data=await api('/api/status');$('det').textContent=data.findings.filter(f=>f.disposition==='REVIEW').length+' review';$('req').textContent=data.audit_count;$('chain').textContent=data.audit_valid?'VERIFIED':'FAILED';$('chain').className=data.audit_valid?'':'err';$('findings').replaceChildren();for(const f of data.findings){const d=el('div',undefined,'finding');const title=el('div');title.append(el('strong',f.agent.toUpperCase()),el('span',f.disposition+' / '+f.score.toFixed(2),'tag '+f.disposition.toLowerCase()));d.append(title,el('div',f.rationale,'minor'),el('div','Evidence: '+(f.evidence.join(', ')||'none'),'refs'),el('div','Limit: '+f.limits,'minor'));$('findings').append(d)}$('pending').replaceChildren();const pending=data.requests.filter(r=>r.status==='PENDING');if(!pending.length)$('pending').append(el('p','No pending approvals'));for(const r of pending){const row=el('div',undefined,'row');row.append(el('span',r.tool+' · '+r.id.slice(0,8)));for(const [caption,decision] of [['Approve once',true],['Reject',false]]){const b=el('button',caption);b.onclick=()=>action('/api/decision',{id:r.id,approve:decision});row.append(b)}$('pending').append(row)}$('history').replaceChildren();for(const r of data.requests.slice(0,30)){const row=el('div',undefined,'row');row.append(el('span',r.tool+' · '+r.id.slice(0,8)),el('span',r.status+' / '+r.mode,'status'));$('history').append(row)}if(!data.requests.length)$('history').append(el('p','No recorded requests yet','minor'));}catch(e){$('result').textContent=e.message;$('result').className='err'}}
async function action(path,data){try{const j=await api(path,data);$('result').textContent=j.status+' — '+j.tool+' / '+j.id.slice(0,8);$('result').className='minor';await refresh()}catch(e){$('result').textContent=e.message;$('result').className='err'}}
$('read').onclick=()=>action('/api/request',{tool:'read_report',args:{report_id:'quarterly-synthetic'},mode:$('mode').value});
$('publish').onclick=()=>action('/api/request',{tool:'publish_external',args:{artifact_id:'quarterly-synthetic',destination:'demo-internal-outbox'},mode:$('mode').value});
$('secret').onclick=()=>action('/api/request',{tool:'read_secret',args:{name:'production-env'},mode:$('mode').value});refresh();
</script></body></html>'''

def serve(log_dir,run_dir,port=8765):
    gateway=Gateway(run_dir);findings=[x.json() for x in hunt(log_dir)];token=secrets.token_urlsafe(30)
    class Handler(BaseHTTPRequestHandler):
        def json(self,status,obj):
            raw=json.dumps(obj,ensure_ascii=False).encode('utf-8')
            self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'");self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def valid_host(self):return self.headers.get('Host') in (f'127.0.0.1:{port}',f'localhost:{port}') and self.client_address[0] in ('127.0.0.1','::1')
        def do_GET(self):
            if not self.valid_host():return self.json(403,{'error':'Localhost only'})
            if self.path=='/api/status':return self.json(200,{**gateway.summary(),'findings':findings})
            if self.path!='/':return self.json(404,{'error':'Not found'})
            raw=HTML.replace('__TOKEN__',json.dumps(token)).encode('utf-8')
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Frame-Options','DENY');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_POST(self):
            if not self.valid_host():return self.json(403,{'error':'Localhost only'})
            if self.headers.get('X-Lab-Token')!=token:return self.json(403,{'error':'Invalid local CSRF token'})
            origin=self.headers.get('Origin');
            if origin and origin not in (f'http://127.0.0.1:{port}',f'http://localhost:{port}'):return self.json(403,{'error':'Untrusted origin'})
            if self.headers.get('Content-Type','').split(';')[0].strip()!='application/json':return self.json(415,{'error':'JSON required'})
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=2048: raise ValueError('Bad request size')
                body=json.loads(self.rfile.read(length))
                if not isinstance(body,dict):raise ValueError('Bad request')
                if self.path=='/api/request':
                    if set(body)!={'tool','args','mode'}:raise ValueError('Bad parameters')
                    outcome=gateway.request(body['tool'],body['args'],body['mode'])
                elif self.path=='/api/decision':
                    if set(body)!={'id','approve'} or not isinstance(body['id'],str):raise ValueError('Bad parameters')
                    outcome=gateway.decide(body['id'],body['approve'])
                else:return self.json(404,{'error':'Not found'})
                return self.json(200,outcome)
            except (ValueError,KeyError,TypeError) as ex:return self.json(400,{'error':str(ex)[:160]})
        def log_message(self,fmt,*args):pass
    server=HTTPServer(('127.0.0.1',port),Handler)
    print(f'AgentGuard dashboard: http://127.0.0.1:{port} (Ctrl+C to stop)',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
