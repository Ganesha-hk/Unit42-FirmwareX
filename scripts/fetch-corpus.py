"""Fetch a frozen public test corpus; never execute firmware."""
import hashlib
import json
from pathlib import Path
import urllib.request
root = Path(__file__).resolve().parents[1]
manifest_path = root / "fixtures/manifests/openwrt-24.10.4.json"
targets = [
 ("x86/64", "openwrt-24.10.4-x86-64-generic-squashfs-rootfs.img.gz"),
 ("x86/64", "openwrt-24.10.4-x86-64-generic-ext4-rootfs.img.gz"),
 ("armsr/armv7", "openwrt-24.10.4-armsr-armv7-generic-squashfs-rootfs.img.gz"),
 ("armsr/armv8", "openwrt-24.10.4-armsr-armv8-generic-squashfs-rootfs.img.gz"),
 ("malta/be", "openwrt-24.10.4-malta-be-rootfs-squashfs.img.gz"),
 ("malta/le", "openwrt-24.10.4-malta-le-rootfs-squashfs.img.gz"),
]
if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text())
else:
    images = []
    for target, name in targets:
        base = "https://downloads.openwrt.org/releases/24.10.4/targets/" + target + "/"
        sums = urllib.request.urlopen(base + "sha256sums", timeout=30).read().decode()
        expected = next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == name)
        images.append({"name": name, "url": base + name, "sha256": expected,
                       "local_name": name + ".bin", "target": target})
    manifest = {
        "version": 1, "frozen_before_analysis": True,
        "license": "OpenWrt build GPL-2.0; component licenses vary; publicly distributed open-source generic/virtual-target images.",
        "license_source": "https://openwrt.org/license",
        "source": "https://github.com/openwrt/openwrt/tree/v24.10.4",
        "success_rule": "Successful extraction; nonempty inventory; at least one correctly detected ELF; no extraction or ELF parse errors.",
        "denominator": 6, "limitations": "One release, generic/virtual targets, SquashFS/ext4; not all vendors or all filesystem formats.",
        "representative_image": images[0]["name"], "images": images}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
output = root / "work/corpus"
output.mkdir(parents=True, exist_ok=True)
for item in manifest["images"]:
    target = output / item["local_name"]
    if not target.exists():
        with urllib.request.urlopen(item["url"], timeout=60) as response:
            target.write_bytes(response.read())
    assert hashlib.sha256(target.read_bytes()).hexdigest() == item["sha256"], item["name"]
print("Fetched and checksum-verified six frozen public images; none executed.")
