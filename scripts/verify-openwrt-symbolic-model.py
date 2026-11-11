"""Run the exact OpenWrt CGI profile directly in the no-network analysis image."""
import json
from pathlib import Path
from uuid import uuid4
from firmwarex.analysis.engine import analyze
from firmwarex.vendor_analysis import OPENWRT_PROFILES

profile=OPENWRT_PROFILES['/usr/libexec/cgi-io']
result=analyze(Path('/fixtures/cgi-io'),str(uuid4()),'/usr/libexec/cgi-io',
    'x86_64',b'controlled-openwrt-symbolic-salt-32-bytes',
    entry=profile['symbolic_entry'],start_context=profile['start_context'],
    budgets={'seconds':40,'memory_mb':512,'steps':1600,'depth':1200})
print(json.dumps({'status':result['status'],'reasons':result['reasons'],
    'telemetry':result['telemetry'],'findings':[
        {'cwe':finding['cwe'],'sink':finding['sink'],'source':finding['source'],
         'confidence':finding['confidence'],'address':finding['address']}
        for finding in result['findings']]}))
