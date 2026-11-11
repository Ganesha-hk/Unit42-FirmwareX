import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
binaries=json.loads((root/'evidence/day1/api-integration.json').read_text())['cases'][0]['binary_audit']['binaries']
s=(root/'evidence/day1/checksec.jsonl').read_text().strip();decoder=json.JSONDecoder();rows=[]
while s:
 check,end=decoder.raw_decode(s);s=s[end:].lstrip()
 for path,result in check.items():
  actual=next(x for x in binaries if x['path']=='/bin/'+path.rsplit('/',1)[1])
  expected={'relro':{'no':'none'}.get(result['relro'],result['relro']),'stack_canary':result['canary']=='yes','nx':result['nx']=='yes','pie':result['pie']=='yes','fortify':result['fortify_source']=='yes','stripped':result['symbols']=='no'}
  assert all(actual[k]==v for k,v in expected.items()),(actual,expected)
  rows.append({'binary':actual['path'],'expected':expected,'pass':True})
(root/'evidence/day1/checksec-comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: 3 controlled variants match 6 checksec fields')
