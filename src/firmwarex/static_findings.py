"""Heuristic static API-use leads; never infer an observed overflow from symbols."""
import hashlib,json
from firmwarex.findings import normalize,ARCHITECTURES
from firmwarex.output_policy import safe_path

def leads(binaries,firmware_id,salt):
    findings=[];evidence={}
    for binary in binaries:
        if binary['architecture'] not in ARCHITECTURES:continue
        for function in binary.get('banned_functions',[]):
            if function not in {'strcpy','strcat','sprintf','gets'}:continue
            detail={'rule':'potentially_dangerous_function_symbol','redacted':True,'heuristic':True,'function':function,'invocation_proven':False,'overflow_proven':False}
            ref='evidence:'+hashlib.sha256(json.dumps(detail,sort_keys=True).encode()).hexdigest()
            findings.append(normalize(firmware_id=firmware_id,binary=safe_path(binary['path'],salt),architecture=binary['architecture'],category='memory_corruption',cwe='CWE-242' if function=='gets' else 'CWE-676',sink=function,evidence_ref=ref,risk_rating='low',confidence='heuristic'))
            evidence[ref]=detail
    return findings,evidence
