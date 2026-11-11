"""Exercise real angr states in the no-network analysis container."""
import json
import angr
from angr import claripy
from firmwarex.analysis.sources import write_source

checks = []
project = angr.Project('/fixtures/analysis/negative', auto_load_libs=False)
for origin in ['cgi_stdin', 'network']:
    for count in [0, 1, 8, 32, 64]:
        state = project.factory.blank_state()
        destination = 0x10000
        state.memory.store(destination, b'Z' * 80)
        written = write_source(state, destination, claripy.BVV(count, 64), origin, 32)
        assert written == min(count, 32)
        assert state.solver.eval(state.memory.load(destination + written, 1)) == ord('Z')
        assert not state.solver.symbolic(state.memory.load(destination + written, 1))
        if written:
            assert state.solver.symbolic(state.memory.load(destination, written))
        checks.append({'origin': origin, 'count': count, 'written': written, 'adjacent_byte_preserved': True})
for count in [0, 1, 64]:
    state = project.factory.blank_state()
    state.memory.store(0x10000, b'Z' * 80)
    written = write_source(state, 0x10000, claripy.BVV(count, 64), 'environment', 32, terminate=True)
    assert written == min(count, 31)
    assert state.solver.eval(state.memory.load(0x10000 + written, 1)) == 0
    assert state.solver.eval(state.memory.load(0x10001 + written, 1)) == ord('Z')
    checks.append({'origin': 'environment', 'count': count, 'written': written, 'terminator': True})
print(json.dumps({'passed': len(checks), 'cases': checks}, indent=2))
