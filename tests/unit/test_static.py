from pathlib import Path
import hashlib
import pytest
from firmwarex.static import audit_elf
from firmwarex.inventory import inventory
from firmwarex.extract import entropy, kind

ROOT = Path("/fixtures/rootfs")

@pytest.mark.parametrize("name,expected", [
    ("strong", {"nx": True, "pie": True, "relro": "full", "stack_canary": True, "fortify": True}),
    ("weak", {"nx": False, "pie": False, "relro": "none", "stack_canary": False, "fortify": False}),
    ("partial", {"nx": True, "pie": True, "relro": "partial", "stack_canary": True, "fortify": False}),
])
def test_compiler_hardening(name, expected):
    actual = audit_elf(ROOT / "bin" / name, ROOT)
    for key, value in expected.items():
        assert actual[key] == value, (name, key, actual)
    assert actual["architecture"] == "x86_64"
    assert actual["endianness"] == "little"
    assert actual["bits"] == 64

def test_shared_library_is_not_pie_executable():
    actual = audit_elf(ROOT / "bin/libfixture.so", ROOT)
    assert actual["elf_type"] == "ET_DYN"
    assert actual["pie"] is False

def test_inventory_never_follows_symlink():
    entries, binaries, errors = inventory(ROOT)
    link = next(x for x in entries if x["path"] == "/etc/external-link")
    assert link["type"] == "symlink"
    assert link["hash"] == hashlib.sha256(b"/outside-not-readable").hexdigest()
    assert len(binaries) == 4
    assert not errors
    assert all({"path", "type", "size", "hash"} <= set(e) for e in entries)

def test_inventory_limit():
    with pytest.raises(ValueError, match="file_count_limit"):
        inventory(ROOT, max_files=1)

def test_inventory_size_limit():
    with pytest.raises(ValueError, match="expanded_size_limit"):
        inventory(ROOT, max_bytes=1)

def test_entropy_and_signature(tmp_path):
    low = tmp_path / "low"
    low.write_bytes(bytes(65536))
    assert entropy(low)[0]["bits_per_byte"] == 0
    high = tmp_path / "high"
    high.write_bytes(bytes(range(256)) * 256)
    assert entropy(high)[0]["bits_per_byte"] == 8
    assert kind(Path("/fixtures/controlled-squashfs.bin")) == "squashfs"

def test_malformed_elf_reported(tmp_path):
    (tmp_path / "bad").write_bytes(b"\x7fELFbroken")
    _, binaries, errors = inventory(tmp_path)
    assert not binaries
    assert errors == [{"path": "/bad", "code": "malformed_elf"}]

@pytest.mark.parametrize("name,architecture,bits,endian", [
    ("mips", "MIPS", 32, "big"), ("mipsel", "MIPSEL", 32, "little"),
    ("arm", "ARM32", 32, "little"), ("aarch64", "ARM64", 64, "little")])
def test_cross_architecture_metadata(name, architecture, bits, endian):
    root = Path('/fixtures/cross')
    result = audit_elf(root / name, root)
    assert (result['architecture'], result['bits'], result['endianness']) == (architecture, bits, endian)
