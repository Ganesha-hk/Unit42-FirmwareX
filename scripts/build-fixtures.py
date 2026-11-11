"""Build but never execute controlled ELF fixtures."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import subprocess
root = Path(__file__).resolve().parents[1]
out = root / "work/fixtures"
tree = out / "rootfs"
(tree / "bin").mkdir(parents=True, exist_ok=True)
(tree / "etc").mkdir(exist_ok=True)
source = root / "fixtures/sources/hardening.c"
variants = {
    "strong": ["-O2", "-fstack-protector-all", "-D_FORTIFY_SOURCE=2", "-fPIE", "-pie", "-Wl,-z,relro,-z,now,-z,noexecstack"],
    "weak": ["-O0", "-fno-stack-protector", "-fno-pie", "-no-pie", "-Wl,-z,norelro,-z,execstack"],
    "partial": ["-O0", "-fstack-protector-all", "-fPIE", "-pie", "-Wl,-z,relro,-z,lazy,-z,noexecstack"],
}
for name, flags in variants.items():
    subprocess.run(["gcc", str(source), "-o", str(tree / "bin" / name), *flags], check=True)
subprocess.run(["gcc", "-shared", "-fPIC", str(source), "-o", str(tree / "bin/libfixture.so")], check=True)
(tree / "etc/fixture.txt").write_text("FirmwareX controlled extraction fixture\n")
link = tree / "etc/external-link"
if not link.is_symlink(): link.symlink_to("/outside-not-readable")
image = out / "controlled-squashfs.bin"
subprocess.run(["mksquashfs", str(tree), str(image), "-noappend", "-all-root", "-no-progress", "-processors", "1", "-mkfs-time", "0", "-all-time", "0"], check=True, stdout=subprocess.DEVNULL)
nested = out / "controlled-nested.bin"
nested.write_bytes(b"FIRMWAREX-CUSTOM-HEADER" + bytes(43) + gzip.compress(image.read_bytes(), mtime=0))
unsupported = out / "unsupported.bin"
unsupported.write_bytes(b"controlled unsupported format\n")
manifest = {"kind": "controlled_fixture", "license_id": "MIT", "executed": False, "images": [
    {"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size}
    for p in [image, nested, unsupported]]}
(out / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("Built controlled ELF and image fixtures; no firmware executed.")
