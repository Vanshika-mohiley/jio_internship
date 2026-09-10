#!/usr/bin/env python3
"""Run the 30-case Base vs RAG vs Full validation benchmark."""
from __future__ import annotations
import argparse,csv,json,re,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from llm import llm_engine
from llm.prompt_builder import build_assessment_prompt,OUTPUT_FORMAT_INSTRUCTIONS
from schema.findings_schema import FindingsList

def toks(s): return set(re.findall(r"[a-z0-9]+",s.lower()))
def retrieve(corpus,query,k=3):
    q=toks(query); scored=[]
    for c in corpus:
        t=toks(f"{c['package']} {c['product']} {c['desc']}"); union=len(q|t) or 1
        scored.append((len(q&t)/union,c))
    scored.sort(key=lambda x:x[0],reverse=True)
    return [c for score,c in scored[:k] if score>0]

def base_prompt(case):
    return f"""You are a vulnerability analyst. Assess this installed package using only the package name and version plus your pretrained knowledge. Do not invent evidence.\n\nPackage: {case['package']}\nInstalled version: {case['version']}\n\nIf you are not confident a real vulnerability applies, return an empty findings list.\n\n{OUTPUT_FORMAT_INSTRUCTIONS}"""

def rag_prompt(case,hits):
    evidence="\n".join(f"- {h['cve']}: {h['package']}; CVSS {h['score']} {h['tier']}; {h['desc']}" for h in hits) or "(none)"
    return f"""You are a vulnerability analyst. Assess the installed package using the package/version and the local RAG evidence below. Treat retrieved CVEs as candidates and verify product/version applicability.\n\nPackage: {case['package']}\nInstalled version: {case['version']}\n\nLOCAL RAG EVIDENCE:\n{evidence}\n\nOnly emit a finding when the evidence supports the exact product/version.\n\n{OUTPUT_FORMAT_INSTRUCTIONS}"""

def full_enrichment(case,by):
    c=by[case['cve']]
    if case['expected_vulnerable'] and case['package']==c['package']:
        return {"matches":[{"package":case['package'],"installed_version":case['version'],"confidence":"exact","confirmed_vulnerability":True,"candidates":[{"cve_id":c['cve'],"product":c['product'],"criteria":f"fixture:{c['vendor']}:{c['product']}","description":c['desc'],"cvss_score":c['score'],"cvss_severity":c['tier'],"match_type":"exact_advisory"}]}],"network_used":False}
    return {"matches":[],"network_used":False}

def full_collection(case):
    return {"schema_version":"1.0","host":{"hostname":f"validation-{case['case_id']}","os_family":"linux","os_version":"benchmark"},"packages":[{"name":case['package'],"version":case['version'],"source":"dpkg"}],"hotfixes":[],"listening_ports":[],"services":[],"suid_binaries":[],"kernel_params":[],"containers":[],"collector_errors":[]}

def call_valid(prompt,model,retries=2):
    last=""; attempts=0
    for attempt in range(1,retries+2):
        attempts=attempt
        raw=llm_engine._call_ollama_raw(prompt if attempt==1 else prompt+f"\n\nPrevious output was invalid: {last}. Return only valid JSON matching the schema.",model=model)
        try:
            result=FindingsList.model_validate(json.loads(llm_engine._extract_json_object(raw)))
            return result,attempts,True
        except Exception as e: last=str(e)
    return None,attempts,False

def classify(result,case):
    findings=[] if result is None else result.findings
    expected=case['expected_cve']; match=next((f for f in findings if expected and expected in f.cve_ids),None)
    predicted=bool(findings)
    if case['expected_vulnerable']:
        tp=bool(match); fp=predicted and not tp; fn=not tp; tier_ok=bool(match and match.severity==case['expected_severity'])
    else:
        tp=False; fp=predicted; fn=False; tier_ok=not predicted
    return {"predicted_finding":predicted,"true_positive":tp,"false_positive":fp,"false_negative":fn,"predicted_severity":(match.severity if match else (findings[0].severity if findings else None)),"cvss_tier_correct":tier_ok}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--cases',default='validation/validation_cases.json'); ap.add_argument('--corpus',default='validation/cve_corpus.json'); ap.add_argument('--out',default='validation/validation_results.csv'); ap.add_argument('--model',required=True); ap.add_argument('--limit',type=int,default=30); args=ap.parse_args()
    root=Path(__file__).resolve().parents[1]; cases=json.loads((root/args.cases).read_text())['cases'][:args.limit]; corpus=json.loads((root/args.corpus).read_text()); by={c['cve']:c for c in corpus}; rows=[]
    for i,case in enumerate(cases,1):
        print(f"[{i}/{len(cases)}] {case['case_id']} {case['package']} {case['version']}")
        prompts={'base':base_prompt(case),'rag':rag_prompt(case,retrieve(corpus,case['package']+' '+case['version'])),'full':build_assessment_prompt(full_collection(case),full_enrichment(case,by))}
        for mode,prompt in prompts.items():
            t=time.time(); result,attempts,valid=call_valid(prompt,args.model); elapsed=round(time.time()-t,2); c=classify(result,case)
            returned=';'.join(sorted({x for f in ([] if result is None else result.findings) for x in f.cve_ids}))
            rows.append({"case_id":case['case_id'],"package":case['package'],"version":case['version'],"expected_vulnerable":case['expected_vulnerable'],"expected_cve":case['expected_cve'] or '',"expected_severity":case['expected_severity'] or '',"mode":mode,"model":args.model,"json_valid":valid,"attempts":attempts,"latency_sec":elapsed,**c,"returned_cves":returned})
    dest=root/args.out; dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('w',newline='',encoding='utf8') as f: w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
    print('\n=== SUMMARY ===')
    for mode in ('base','rag','full'):
        r=[x for x in rows if x['mode']==mode]; tp=sum(x['true_positive'] for x in r); fp=sum(x['false_positive'] for x in r); fn=sum(x['false_negative'] for x in r); valid=sum(x['json_valid'] for x in r); tier=sum(x['cvss_tier_correct'] for x in r)
        p=tp/(tp+fp) if tp+fp else 0; rec=tp/(tp+fn) if tp+fn else 0; f1=2*p*rec/(p+rec) if p+rec else 0
        print(f"{mode:5s} precision={p:.3f} recall={rec:.3f} f1={f1:.3f} cvss_tier_accuracy={tier/len(r):.3f} json_validity={valid/len(r):.3f}")
    print(f"\nResults: {dest}")
if __name__=='__main__': main()
