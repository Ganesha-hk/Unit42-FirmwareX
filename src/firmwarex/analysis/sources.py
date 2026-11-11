"""Bounded input models; byte streams must not acquire string terminators."""
from angr import claripy


def write_source(state, destination, count, origin, source_bytes, *, terminate=False):
    capacity = source_bytes - 1 if terminate else source_bytes
    width = min(state.solver.eval(count), capacity)
    ordinal = state.globals.get('fwx_source_count', 0)
    state.globals['fwx_source_count'] = ordinal + 1
    if width:
        value = claripy.BVS(f'fwx_{origin}_{ordinal}', width * 8, explicit_name=True)
        for byte in value.chop(8):
            state.solver.add(byte >= 0x20, byte <= 0x7e)
        state.memory.store(destination, value)
    if terminate:
        state.memory.store(destination + width, claripy.BVV(0, 8))
    return width
