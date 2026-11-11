"""Graph export preserves topology and reports bounded coverage."""
import sys
from types import SimpleNamespace
from firmwarex.pipeline import graph_for
from firmwarex.output_policy import sanitize_output


def test_graph_limits_and_redaction(monkeypatch):
    nodes=[SimpleNamespace(addr=0x400000+i) for i in range(300)]
    graph=SimpleNamespace(nodes=lambda:nodes,edges=lambda:list(zip(nodes,nodes[1:])))
    function=SimpleNamespace(addr=0x400000,name='private_symbol',graph=graph)
    project=SimpleNamespace(loader=SimpleNamespace(find_symbol=lambda _:None,main_object=SimpleNamespace(contains_addr=lambda _:True)),analyses=SimpleNamespace(CFGFast=lambda **_:SimpleNamespace(kb=SimpleNamespace(functions={1:function}))))
    monkeypatch.setitem(sys.modules,'angr',SimpleNamespace(Project=lambda *a,**k:project))
    result=graph_for('/unused', [['0x400001']])
    assert result['status']=='incomplete'
    assert result['incomplete']
    f=result['functions'][0]
    assert len(f['nodes'])==256 and len(f['edges'])==255
    assert f['nodes'][1]['tainted']
    ids={n['id'] for n in f['nodes']}
    assert all(e['source'] in ids and e['target'] in ids for e in f['edges'])
    assert f['name']=='function_0x400000'
    assert sanitize_output(result,b'x'*32)==result
