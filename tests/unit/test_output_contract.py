"""The output policy preserves reviewed diagnostic schema, including graph edges."""
from firmwarex.output_policy import sanitize_output

def test_graph_edges_remain_connected():
 graph={'graphs':{'/bin/taint-demo':{'functions':[{'name':'main','nodes':[{'id':'0x401000'},{'id':'0x401010'}],'edges':[{'source':'0x401000','target':'0x401010'}]}]}}}
 assert sanitize_output(graph,b'x'*32)==graph

def test_pipeline_image_needs_no_database_for_output_filter():
 import subprocess,sys
 code="import sys;sys.modules['sqlalchemy']=None;from firmwarex.output_policy import sanitize_output;assert sanitize_output({'description':'PRIVATE'},b'x'*32)['description'].startswith('redacted-')"
 subprocess.run([sys.executable,'-c',code],check=True)
