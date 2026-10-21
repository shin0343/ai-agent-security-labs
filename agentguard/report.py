"""Evidence-linked case export and transparent synthetic evaluation."""
from pathlib import Path
from .hunt import hunt, inspect_ref
from .gateway import Gateway
import json, csv

def evaluate(log_dir):
    findings=hunt(log_dir)
    # Synthetic policy-outcome labels; UNKNOWN intentionally excluded.
    gold={'build':False,'data':True,'helpdesk':True,'docs':None}
    known=[f for f in findings if gold[f.agent] is not None]
    stats={'TP':0,'FP':0,'TN':0,'FN':0,'UNKNOWN':sum(gold[f.agent] is None for f in findings)}
    for f in known:
        pred=f.disposition=='REVIEW'; actual=gold[f.agent]
        stats[('TP' if actual else 'FP') if pred else ('FN' if actual else 'TN')]+=1
    p=stats['TP']/(stats['TP']+stats['FP']) if stats['TP']+stats['FP'] else None
    r=stats['TP']/(stats['TP']+stats['FN']) if stats['TP']+stats['FN'] else None
    f1=(2*p*r/(p+r)) if p is not None and r is not None and p+r else None
    return {'dataset':'4 independently authored synthetic agents, 3 known labels; not real-world detector performance', 'counts':stats,'precision':p,'recall':r,'f1':f1,'predictions':[f.json() for f in findings]}

def export_case(log_dir,run_dir):
    gw=Gateway(run_dir)
    report_dir=Path(run_dir)/'reports';report_dir.mkdir(parents=True,exist_ok=True)
    findings=hunt(log_dir)
    out=['# [LAB] Synthetic Agent Incident — Analyst Case Draft','','**Classification:** synthetic / educational / not a real compromise.','**Workflow:** Triage → Investigation → Finding → Case → Approval Audit.', '**Vigil:** manually enter this case into your local Vigil SOC; NO API POST or automatic finding creation.','', '## Triage — evidence-based priorities','']
    for f in findings:
        out+= [f'### {f.agent.upper()} — {f.disposition} (illustrative risk score {f.score:.2f})',f'- Observation: {f.rationale}',f'- What remains unknown: {f.limits}', '- Source evidence: '+(', '.join(f'`{r}`' for r in f.evidence) if f.evidence else '(none)'), '']
        for ref in f.evidence:
            value=inspect_ref(log_dir,ref)
            # All content here from deterministic synthetic generator, not real source logs.
            out += [f'  - `{ref}`: `{json.dumps(value,ensure_ascii=False,sort_keys=True)}`']
        out+=['']
    out += ['## Investigation / tool execution gate',f'- Audit HMAC chain verified: **{gw.audit.verify()}**',f'- Tool decisions recorded: **{len(gw.audit.read())}**', '- Audit contains request metadata and argument digests, not sensitive tool bodies.','']
    for item in gw.summary()['requests']:
        out.append(f"- `{item['id']}` `{item['tool']}` → **{item['status']}** ({item['mode']})")
    out+=['','## Case adjudication and limitations','- Do not equate an IDS alert or TLS session with successful exfiltration.','- Build and Data share a host/IP: network identity does NOT confirm process or agent attribution.','- `APPROVED` and `MONITORED` only write local receipts; no real external publishing.','- Unknown Docs authorization remains UNKNOWN rather than automatically malicious.','- Next steps: verify asset and process telemetry, scope approvals, real-world baselines, and independent data.']
    path=report_dir/'vigil_case_draft.md';path.write_text('\n'.join(out)+'\n',encoding='utf-8')
    metrics=evaluate(log_dir); (report_dir/'evaluation.json').write_text(json.dumps(metrics,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    with (report_dir/'findings.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.writer(f);writer.writerow(('agent','score','disposition','evidence_refs'))
        for finding in findings:writer.writerow((finding.agent,finding.score,finding.disposition,';'.join(finding.evidence)))
    return path
