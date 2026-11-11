import importlib.metadata as md,json
rows=[]
for d in sorted(md.distributions(),key=lambda d:d.metadata['Name'].lower()):
 m=d.metadata
 rows.append({'name':m['Name'],'version':d.version,'license_expression':m.get('License-Expression'),'license':m.get('License'),'license_classifiers':[c for c in m.get_all('Classifier',[]) if c.startswith('License ::')],'project_urls':m.get_all('Project-URL',[])})
print(json.dumps(rows,indent=2))
