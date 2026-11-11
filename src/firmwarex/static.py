"""ELF metadata is parsed without executing the target."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

ARCHES = {"EM_ARM": "ARM32", "EM_AARCH64": "ARM64", "EM_X86_64": "x86_64", "EM_386": "x86"}

def audit_elf(path: Path, root: Path) -> dict | None:
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            return None
        stream.seek(0)
        elf = ELFFile(stream)
        machine = elf.header["e_machine"]
        arch = ("MIPSEL" if elf.little_endian else "MIPS") if machine == "EM_MIPS" else ARCHES.get(machine, str(machine))
        names = set()
        stripped = True
        for section in elf.iter_sections():
            if section.name == ".symtab":
                stripped = False
            if isinstance(section, SymbolTableSection):
                names.update(symbol.name for symbol in section.iter_symbols())
        stack = None
        relro = False
        bind_now = False
        wx = []
        interpreter = False
        pie_flag = False
        for seg in elf.iter_segments():
            kind = seg.header.p_type
            if kind == "PT_GNU_STACK":
                stack = not bool(seg.header.p_flags & 1)
            if kind == "PT_GNU_RELRO":
                relro = True
            if kind == "PT_INTERP":
                interpreter = True
            if kind == "PT_LOAD" and seg.header.p_flags & 3 == 3:
                wx.append(hex(seg.header.p_vaddr))
            if kind == "PT_DYNAMIC":
                for tag in seg.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS":
                        bind_now |= bool(tag.entry.d_val & 8)
                    if tag.entry.d_tag == "DT_FLAGS_1":
                        bind_now |= bool(tag.entry.d_val & 1)
                        pie_flag |= bool(tag.entry.d_val & 0x08000000)
        etype = elf.header.e_type
        # ET_DYN shared libraries are relocatable, but are not PIE executables.
        pie = etype == "ET_DYN" and (interpreter or pie_flag)
        return {
            "path": "/" + path.relative_to(root).as_posix(), "architecture": arch,
            "endianness": "little" if elf.little_endian else "big", "bits": elf.elfclass,
            "elf_type": etype, "nx": stack, "pie": pie,
            "relro": "full" if relro and bind_now else "partial" if relro else "none",
            "stack_canary": any(n.split("@")[0] in {"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"} for n in names),
            "fortify": any(n.split("@")[0].startswith("__") and n.split("@")[0].endswith("_chk") for n in names),
            "stripped": stripped, "wx_segments": wx,
            "banned_functions": sorted(names & {"strcpy", "strcat", "gets", "sprintf"}),
            "limitations": ["Missing symbols may conceal canary/FORTIFY use; PIE does not prove runtime ASLR."]
        }
