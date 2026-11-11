"""Bounded angr source-to-sink analysis. Hooks never invoke host commands."""
import hashlib
import json
import logging
import resource
import time
from dataclasses import asdict
import angr
from angr import claripy
from firmwarex.analysis.bounds import object_bounds, locate
from firmwarex.findings import normalize
from firmwarex.scanners.secrets import fingerprint
from firmwarex.analysis.sources import write_source
from firmwarex.analysis.budgets import Budgets

for name in ('angr','cle','claripy','pyvex'):logging.getLogger(name).setLevel(logging.CRITICAL)

def analyze(path,firmware_id,binary,architecture,salt,budgets=None,entry='main',start_context=None):
    budget=Budgets(**(budgets or {}));start=time.monotonic();findings=[];evidence={};reasons=set();counts={'steps':0,'paths':1,'pruned':0,'merged':0,'peak_states':1,'terminal_returns':[]}
    project=angr.Project(str(path),auto_load_libs=False)
    globals_,locals_=object_bounds(path)
    expected={'AMD64':'x86_64','ARMEL':'ARM32','ARMHF':'ARM32','AARCH64':'ARM64','MIPS32':'MIPSEL' if project.arch.memory_endness=='Iend_LE' else 'MIPS'}
    if expected.get(project.arch.name)!=architecture:raise ValueError('architecture mismatch')
    bias=project.loader.main_object.mapped_base-project.loader.main_object.linked_base
    def sources(ast):return sorted(v for v in ast.variables if v.startswith('fwx_'))
    def expression(ast,depth=0):
        if depth>64:
            reasons.add('condition_budget');return {'truncated':True}
        if not hasattr(ast,'op'):return ast if isinstance(ast,(int,bool)) else 'redacted'
        if ast.op=='BVS':return {'symbol':ast.args[0] if ast.args[0].startswith('fwx_') else 'unmodeled','bits':ast.size()}
        if ast.op=='BVV':return {'constant':ast.args[0],'bits':ast.size()} if ast.size()<=64 else {'fingerprint':fingerprint(str(ast.args[0]).encode(),salt),'bits':ast.size()}
        return {'op':ast.op,'args':[expression(arg,depth+1) for arg in ast.args]}
    def registers(state):
        result={}
        for name in ({'AMD64':['rip','rsp','rbp','rax','rdi','rsi','rdx'],'ARMEL':['pc','sp','r0','r1'],'AARCH64':['pc','sp','x0','x1']}.get(state.arch.name,['pc','sp'])):
            value=getattr(state.regs,name)
            if state.solver.symbolic(value):result[name]={'symbolic':True,'sources':sources(value)}
            else:
                concrete=state.solver.eval(value);sp=state.solver.eval(state.regs.sp)
                result[name]=hex(concrete) if name in {'pc','sp','rip','rsp','rbp'} else {'fingerprint':fingerprint(str(concrete).encode(),salt)}
        return result
    def emit(state,sink,taint,cwe,kind,overflow=None,fault=None,condition=None):
        history=[int(x) for x in state.history.bbl_addrs.hardcopy]
        path_hex=[hex(x) for x in history[-256:]]
        callpath=[hex(frame.call_site_addr) for frame in state.callstack if frame.call_site_addr]
        source_names=sorted({v for value in taint for v in sources(value)})
        constraints=list(state.solver.constraints)+( [condition] if condition is not None else [])
        if len(constraints)>128:reasons.add('condition_budget')
        detail={'kind':kind,'sources':source_names,'condition':[expression(c) for c in constraints[:128]],'condition_satisfiable':True,'call_path':callpath,'alternative_paths':state.globals.get('fwx_paths',[]),'redacted':True}
        digest=fingerprint(json.dumps(detail,sort_keys=True).encode(),salt);ref='evidence:'+digest;evidence[ref]=detail
        stack_hash=hashlib.sha256(json.dumps(callpath).encode()).hexdigest()
        finding=normalize(firmware_id=firmware_id,binary=binary,architecture=architecture,category='command_injection' if cwe=='CWE-78' else 'memory_corruption',cwe=cwe,evidence_ref=ref,address=hex(history[-1]) if history else None,sink=sink,source=','.join(source_names) or None,tainted_path=path_hex,crash_state={'fault_address':hex(fault) if fault is not None else None,'registers':registers(state),'overflow_offset':overflow,'stack_hash':stack_hash},confidence='heuristic' if kind=='tainted_copy_unknown_object_bounds' else 'probable',risk_rating='high')
        findings.append(finding)
    def source(state,dst,count,origin,terminate=False):
        return write_source(state,dst,count,origin,budget.source_bytes,terminate=terminate)
    class Read(angr.SimProcedure):
        def run(self,fd,dst,count):
            if (start_context or {}).get('stdin_eof') and self.state.solver.is_true(fd==0):
                return 0
            return source(self.state,dst,count,'cgi_stdin')
    class Recv(angr.SimProcedure):
        def run(self,fd,dst,count,flags):return source(self.state,dst,count,'network')
    class Getenv(angr.SimProcedure):
        def run(self,name):
            key=self.state.mem[name].string.concrete
            context=start_context or {}
            if isinstance(context.get('environment'),dict):
                label=key.decode('ascii',errors='replace')
                cache=dict(self.state.globals.get('fwx_environment_cache',{}))
                if label in cache:return cache[label]
                values=context['environment']
                symbolic=context.get('symbolic_environment',[])
                if label not in values and label not in symbolic:return 0
                if label in values:
                    value=values[label].encode()+b'\0'
                    dst=self.state.heap.allocate(len(value))
                    self.state.memory.store(dst,value)
                else:
                    dst=self.state.heap.allocate(budget.source_bytes)
                    source(self.state,dst,claripy.BVV(budget.source_bytes-1,self.state.arch.bits),'environment',terminate=True)
                    prefix=context.get('symbolic_environment_prefixes',{}).get(label,'')
                    if not isinstance(prefix,str) or len(prefix.encode())>=budget.source_bytes:
                        raise ValueError('invalid symbolic environment prefix')
                    for offset,byte in enumerate(prefix.encode()):
                        self.state.solver.add(self.state.memory.load(dst+offset,1)==byte)
                cache[label]=dst
                self.state.globals['fwx_environment_cache']=cache
                return dst
            dst=self.state.heap.allocate(budget.source_bytes)
            source(self.state,dst,claripy.BVV(budget.source_bytes-1,self.state.arch.bits),'cgi_query' if key==b'QUERY_STRING' else 'environment',terminate=True)
            return dst
    class Malloc(angr.SIM_PROCEDURES['libc']['malloc']):
        def run(self,size):
            if self.state.solver.symbolic(size):
                allocation_limit=budget.source_bytes*2
                # Keep the bounded model sound for the states we retain. If a
                # larger allocation is also possible, make that lost coverage
                # explicit rather than reporting the remaining path complete.
                if not self.state.solver.satisfiable(extra_constraints=[claripy.ULE(size,allocation_limit)]):
                    reasons.add('symbolic_allocation_budget')
                    self.exit(0)
                    return 0
                if self.state.solver.satisfiable(extra_constraints=[claripy.UGT(size,allocation_limit)]):
                    reasons.add('symbolic_allocation_truncated')
                self.state.solver.add(claripy.ULE(size,allocation_limit))
                # Reserve the maximum bounded backing region while retaining
                # the requested symbolic object size for overflow proofs.
                result=self.state.heap.allocate(allocation_limit)
            else:
                result=super().run(size)
            if not self.state.solver.symbolic(result):
                base=self.state.solver.eval(result)
                if self.state.solver.symbolic(size):
                    self.state.globals['fwx_symbolic_allocations']=tuple(self.state.globals.get('fwx_symbolic_allocations',()))+((base,size),)
                else:
                    self.state.globals['fwx_allocations']=tuple(self.state.globals.get('fwx_allocations',()))+((base,self.state.solver.eval(size),'heap'),)
            return result
    class Strlen(angr.SimProcedure):
        def run(self,src):return string_length(self.state,src)
    class ErrnoLocation(angr.SimProcedure):
        def run(self):
            # musl's __errno_location returns thread-local writable storage.
            # Returning null creates false CWE-476 reports on ordinary error
            # paths such as cgi-io's CONTENT_TYPE validation.
            address=self.state.globals.get('fwx_errno_address')
            if address is None:
                address=self.state.heap.allocate(4)
                self.state.memory.store(address,claripy.BVV(0,32),endness=self.state.arch.memory_endness)
                self.state.globals['fwx_errno_address']=address
            return address
    def sink_event(proc,dst,src,length,name,fmt=False):
        state=proc.state;content=state.memory.load(src,budget.source_bytes)
        if not sources(content) and not sources(length):return
        if dst is not None and not state.solver.symbolic(dst):
            address=state.solver.eval(dst)
            for base,size in state.globals.get('fwx_symbolic_allocations',()):
                if base<=address and state.solver.is_true(claripy.ULE(address-base,size)):
                    capacity=size-(address-base)
                    if not state.solver.satisfiable(extra_constraints=[claripy.UGT(length,capacity)]):
                        counts['proven_safe_copies']=counts.get('proven_safe_copies',0)+1
                        return
                    if state.solver.satisfiable(extra_constraints=[claripy.UGT(length,capacity)]):
                        emit(state,name,[content,length],'CWE-122','modeled_out_of_bounds_write',None,None,claripy.UGT(length,capacity));proc.exit(0);return
        bounds=locate(state,dst,globals_,locals_,bias) if dst is not None else None
        if name in {'system','popen'}:emit(state,name,[content],'CWE-78','tainted_command_sink');proc.exit(0);return
        if fmt:emit(state,name,[content],'CWE-134','tainted_format_sink');proc.exit(0);return
        if bounds:
            address,capacity,region=bounds;condition=claripy.UGT(length,capacity)
            if state.solver.satisfiable(extra_constraints=[condition]):
                emit(state,name,[content,length],{'stack':'CWE-121','heap':'CWE-122','global':'CWE-787'}[region],'modeled_out_of_bounds_write',capacity,address+capacity,condition);proc.exit(0)
        else:
            emit(state,name,[content,length],'CWE-120','tainted_copy_unknown_object_bounds');proc.exit(0)
    def string_length(state,src):
        possibilities=[]
        for index in range(budget.source_bytes):
            byte=state.memory.load(src+index,1)
            if state.solver.is_true(byte==0):
                length=claripy.BVV(index,state.arch.bits)
                for offset,condition in reversed(possibilities):length=claripy.If(condition,claripy.BVV(offset,state.arch.bits),length)
                return length
            if state.solver.satisfiable(extra_constraints=[byte==0]):possibilities.append((index,byte==0))
        reasons.add('string_budget')
        return claripy.BVV(budget.source_bytes,state.arch.bits)
    def copy_effect(proc,dst,src,length):
        if proc.state.solver.symbolic(length):
            reasons.add('symbolic_copy_length');proc.exit(0);return
        count=proc.state.solver.eval(length)
        if count>budget.source_bytes:reasons.add('copy_budget');proc.exit(0);return
        if count:proc.state.memory.store(dst,proc.state.memory.load(src,count))
    class Strcpy(angr.SimProcedure):
        def run(self,dst,src):
            length=string_length(self.state,src)+1
            sink_event(self,dst,src,length,'strcpy');copy_effect(self,dst,src,length);return dst
    class Memcpy(angr.SimProcedure):
        def run(self,dst,src,length):sink_event(self,dst,src,length,'memcpy');copy_effect(self,dst,src,length);return dst
    class Sprintf(angr.SimProcedure):
        def run(self,dst,fmt,value):
            format_ast=self.state.memory.load(fmt,budget.source_bytes)
            if sources(format_ast):sink_event(self,dst,fmt,claripy.BVV(0,self.state.arch.bits),'sprintf',True)
            elif self.state.mem[fmt].string.concrete==b'%s':
                length=string_length(self.state,value)+1
                sink_event(self,dst,value,length,'sprintf');copy_effect(self,dst,value,length)
            else:reasons.add('unsupported_format')
            return 0
    class System(angr.SimProcedure):
        def run(self,command):sink_event(self,None,command,claripy.BVV(0,self.state.arch.bits),'system');return 0
    class Popen(angr.SimProcedure):
        def run(self,command,mode):sink_event(self,None,command,claripy.BVV(0,self.state.arch.bits),'popen');return 0
    for name,hook in {'read':Read,'recv':Recv,'getenv':Getenv,'malloc':Malloc,'__errno_location':ErrnoLocation,'strlen':Strlen,'strcpy':Strcpy,'memcpy':Memcpy,'sprintf':Sprintf,'system':System,'popen':Popen}.items():
        if project.loader.find_symbol(name):project.hook_symbol(name,hook())
    options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.options.STRICT_PAGE_ACCESS}
    if entry=='program_entry':
        # Stripped vendor executables often have no main symbol. Start from the
        # actual ELF entry with startup state, rather than inventing main.
        state=project.factory.entry_state(args=[binary],add_options=options)
        reasons.add('program_entry_limited_models')
    elif entry.startswith('address:'):
        # A profile may use an address recovered from the binary's own CFG.
        # This bypasses loader initialization only after the caller records
        # the address and input/sink evidence that justify the entry point.
        try:
            address=int(entry.split(':',1)[1],16)
        except ValueError: raise ValueError('invalid entry address') from None
        if not project.loader.main_object.contains_addr(address):
            raise ValueError('entry address outside main object')
        # Model a normal C ``main(int argc, char **argv, char **envp)`` call.
        # Passing null argv caused real programs to fail before reaching their
        # input handlers and was incorrectly reported as an engine limitation.
        if project.arch.name!='AMD64':raise ValueError('profiled address entry requires architecture startup model')
        context=start_context or {}
        if set(context)-{'argv0','environment','symbolic_environment','symbolic_environment_prefixes','working_directory','stdin_eof'}:raise ValueError('invalid start context')
        argv0=context.get('argv0',binary)
        if not isinstance(argv0,str) or not argv0.startswith('/') or len(argv0)>256:raise ValueError('invalid argv0')
        pointer=project.arch.bytes
        state=project.factory.call_state(address,1,0,0,add_options=options)
        argv=state.solver.eval(state.regs.sp)+0x100
        arg0=argv+pointer*2
        state.memory.map_region(argv & ~0xfff,0x1000,3)
        state.memory.store(argv,claripy.BVV(arg0,project.arch.bits),endness=project.arch.memory_endness)
        state.memory.store(argv+pointer,claripy.BVV(0,project.arch.bits),endness=project.arch.memory_endness)
        state.memory.store(arg0,argv0.encode()+b'\0')
        state.regs.rsi=argv
        cwd=context.get('working_directory','/')
        if cwd!='/':raise ValueError('unsupported working directory')
        state.fs.cwd=b'/'
        state.globals['fwx_start_context']={'argc':1,'argv0':argv0,
            'environment':'named_environment' if isinstance(context.get('environment'),dict) else 'getenv_model',
            'symbolic_environment':context.get('symbolic_environment',[]),
            'working_directory':'/', 'stdin_eof':bool(context.get('stdin_eof')),
            'symbolic_environment_prefixes':sorted(context.get('symbolic_environment_prefixes',{}))}
    else:
        symbol=project.loader.find_symbol(entry)
        if not symbol:raise ValueError('entry_symbol_required')
        state=project.factory.call_state(symbol.rebased_addr,prototype='int main(void)',add_options=options)
    def remember_write(current):current.globals['fwx_memory_access']='write'
    def remember_read(current):current.globals['fwx_memory_access']='read'
    def terminal_return(current):
        register={'AMD64':'rax','ARMEL':'r0','ARMHF':'r0','AARCH64':'x0','MIPS32':'v0'}.get(current.arch.name)
        if register is None:return 'unsupported'
        value=getattr(current.regs,register)
        return 'symbolic' if current.solver.symbolic(value) else current.solver.eval(value)
    state.inspect.b('mem_write',when=angr.BP_BEFORE,action=remember_write)
    state.inspect.b('mem_read',when=angr.BP_BEFORE,action=remember_read)
    state.solver._solver.timeout=1000
    sim=project.factory.simgr(state,save_unconstrained=True)
    while sim.active:
        if time.monotonic()-start>=budget.seconds:reasons.add('time_budget');break
        if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024>=budget.memory_mb:reasons.add('memory_budget');break
        if counts['steps']>=budget.steps:reasons.add('step_budget');break
        if counts['paths']>=budget.paths:reasons.add('path_budget');break
        before=len(sim.active);sim.step();counts['steps']+=1
        counts['paths']+=max(0,len(sim.active)+len(sim.deadended)-before)
        for terminal in sim.deadended:
            if len(counts['terminal_returns'])<32:counts['terminal_returns'].append(terminal_return(terminal))
        sim.drop(stash='deadended')
        sim.prune();counts['pruned']+=len(sim.pruned);sim.drop(stash='pruned')
        deep=[s for s in sim.active if s.history.depth>=budget.depth]
        if deep:reasons.add('depth_budget');counts['pruned']+=len(deep);sim.active[:]=[s for s in sim.active if s.history.depth<budget.depth]
        counts['peak_states']=max(counts['peak_states'],len(sim.active))
        if budget.merge and len(sim.active)>1:
            # Merge only compatible source/allocation contexts and preserve alternative paths.
            groups={}
            for s in sim.active:
                key=(s.addr,s.callstack.func_addr,s.callstack.stack_ptr,s.globals.get('fwx_source_count',0),s.globals.get('fwx_allocations',()))
                groups.setdefault(key,[]).append(s)
            active=[]
            for group in groups.values():
                if len(group)==1:active+=group;continue
                merged,_,changed=group[0].merge(*group[1:])
                if changed:
                    merged.globals['fwx_paths']=[[hex(a) for a in s.history.bbl_addrs.hardcopy][-256:] for s in group]
                    counts['merged']+=len(group)-1;active.append(merged)
                else:active+=group
            sim.active[:]=active
        if len(sim.active)>budget.states:
            reasons.add('state_budget');counts['pruned']+=len(sim.active)-budget.states;sim.active[:]=sim.active[:budget.states]
        if sim.unconstrained:reasons.add('unconstrained_state');sim.drop(stash='unconstrained')
    for record in sim.errored:
        error=record.error
        # ErrorRecord.state predates the failing block. Recover the fault-time
        # SimState from angr's own traceback; never serialize frame locals.
        fault_state=record.state;trace=record.traceback
        while trace is not None:
            candidate=getattr(trace.tb_frame.f_locals.get('self'),'state',None)
            if isinstance(candidate,angr.SimState):fault_state=candidate
            trace=trace.tb_next
        if (isinstance(error,angr.errors.SimSegfaultException)
                and fault_state.globals.get('fwx_memory_access')=='write'
                and isinstance(error.addr,int) and error.addr == 0):
            emit(fault_state,None,[],'CWE-476','symbolic_null_write',fault=0)
            if entry.startswith('address:'):
                # A function-entry profile bypasses loader/library setup. Keep
                # the diagnostic, but do not equate a model fault with a
                # probable crash in the real firmware process.
                findings[-1]['confidence']='heuristic'
                reasons.add('profile_memory_fault_requires_validation')
        else:reasons.add('engine_error_'+type(error).__name__)
    return {'status':'incomplete' if reasons else 'completed','reasons':sorted(reasons),'start_context':state.globals.get('fwx_start_context'),'budgets':asdict(budget),'telemetry':{**counts,'wall_seconds':round(time.monotonic()-start,3)},'findings':list({f['vulnerability_id']:f for f in findings}.values()),'evidence':evidence,'limitations':['Source models use bounded printable bytes, not exhaustive inputs.','Exploration stops at candidate sink violations; bounded safe copies preserve taint.','Stack bounds require supported DWARF x86_64 frame-pointer ABI.','No concrete command or exploit input is generated.']}
