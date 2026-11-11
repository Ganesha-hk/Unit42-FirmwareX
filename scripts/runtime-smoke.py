import json,sys
import angr
import unicorn
import z3
p=angr.Project('/fixtures/rootfs/bin/strong',auto_load_libs=False)
cfg=p.analyses.CFGFast()
x=z3.Int('x'); solver=z3.Solver(); solver.add(x>2,x<4)
assert solver.check()==z3.sat
u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
u.mem_map(0x1000,4096);u.mem_write(0x1000,b'\x90');u.emu_start(0x1000,0x1001,count=1)
print(json.dumps({'python':sys.version.split()[0],'angr':angr.__version__,'unicorn':unicorn.__version__,'functions':len(cfg.kb.functions),'solver':'sat','controlled_unicorn_nop':'pass'}))
