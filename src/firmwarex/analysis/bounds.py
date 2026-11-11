"""Object bounds from ELF/DWARF and modeled allocations; never guess stack sizes."""
from elftools.elf.elffile import ELFFile

def object_bounds(path):
    globals_=[]; locals_=[]
    with open(path,'rb') as stream:
        elf=ELFFile(stream)
        for section in elf.iter_sections():
            if section.header.sh_type in {'SHT_SYMTAB','SHT_DYNSYM'}:
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type']=='STT_OBJECT' and symbol['st_size']:
                        globals_.append((int(symbol['st_value']),int(symbol['st_size']),'global'))
        if elf.header.e_machine=='EM_X86_64' and elf.has_dwarf_info():
            from elftools.dwarf.dwarf_expr import DWARFExprParser
            dwarf=elf.get_dwarf_info()
            def size(die):
                if die is None:return None
                if 'DW_AT_byte_size' in die.attributes:return die.attributes['DW_AT_byte_size'].value
                if die.tag in {'DW_TAG_typedef','DW_TAG_const_type','DW_TAG_volatile_type'}:return size(die.get_DIE_from_attribute('DW_AT_type'))
                if die.tag=='DW_TAG_array_type':
                    base=size(die.get_DIE_from_attribute('DW_AT_type'));count=1
                    for child in die.iter_children():
                        if 'DW_AT_count' in child.attributes:count*=child.attributes['DW_AT_count'].value
                        elif 'DW_AT_upper_bound' in child.attributes:count*=child.attributes['DW_AT_upper_bound'].value+1
                        else:return None
                    return base*count if base else None
                return None
            for cu in dwarf.iter_CUs():
                parser=DWARFExprParser(cu.structs)
                for function in cu.iter_DIEs():
                    if function.tag!='DW_TAG_subprogram' or 'DW_AT_low_pc' not in function.attributes or 'DW_AT_high_pc' not in function.attributes:continue
                    frame=function.attributes.get('DW_AT_frame_base')
                    if not frame or [op.op_name for op in parser.parse_expr(frame.value)]!=['DW_OP_call_frame_cfa']:continue
                    low=function.attributes['DW_AT_low_pc'].value;high=function.attributes['DW_AT_high_pc'];end=high.value if high.form=='DW_FORM_addr' else low+high.value
                    for variable in function.iter_children():
                        if variable.tag!='DW_TAG_variable' or 'DW_AT_location' not in variable.attributes or 'DW_AT_type' not in variable.attributes:continue
                        ops=parser.parse_expr(variable.attributes['DW_AT_location'].value)
                        width=size(variable.get_DIE_from_attribute('DW_AT_type'))
                        if width and len(ops)==1 and ops[0].op_name=='DW_OP_fbreg':locals_.append((low,end,ops[0].args[0],width))
    return globals_,locals_

def locate(state,destination,globals_,locals_,bias):
    if state.solver.symbolic(destination):return None
    address=state.solver.eval(destination)
    for base,length,kind in tuple(state.globals.get('fwx_allocations',()))+tuple((a+bias,n,k) for a,n,k in globals_):
        if base<=address<base+length:return (address,base+length-address,kind)
    # Supported O0 x86_64 frame-pointer ABI only; all other frames remain unknown.
    history=list(state.history.bbl_addrs.hardcopy)
    if state.arch.name=='AMD64' and not state.solver.symbolic(state.regs.rbp):
        bp=state.solver.eval(state.regs.rbp)
        for low,end,offset,length in locals_:
            if any(low+bias<=pc<end+bias for pc in history[-8:]):
                base=bp+16+offset
                if base<=address<base+length:return (address,base+length-address,'stack')
    return None
