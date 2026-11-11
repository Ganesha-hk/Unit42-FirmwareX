"""Bounded extraction adapters. Called only inside the offline sandbox."""
import bz2
import gzip
import hashlib
import lzma
import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

MAX_BYTES = 512 * 1024 * 1024
MAX_CANDIDATES = 64

def entropy(path: Path):
    windows = []
    with path.open("rb") as f:
        offset = 0
        while block := f.read(65536):
            n = len(block)
            value = -sum((c/n) * math.log2(c/n) for c in Counter(block).values())
            windows.append({"offset": offset, "size": n, "bits_per_byte": round(value, 6)})
            offset += n
    return windows

def run_tool(args, timeout=90):
    # Tool output can contain firmware strings. It is not exported or logged.
    with open("/dev/null", "wb") as sink:
        done = subprocess.run(args, stdout=sink, stderr=sink, timeout=timeout, check=False)
    if done.returncode:
        raise ValueError("extractor_exit_" + str(done.returncode))

def kind(path):
    with path.open("rb") as f:
        head = f.read(2048)
    if head[:4] in (b"hsqs", b"sqsh", b"shsq", b"qshs"): return "squashfs"
    if head[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"): return "cramfs"
    if head[:4] in (b"UBI#", b"\x31\x18\x10\x06"): return "ubifs"
    if head[:2] in (b"\x85\x19", b"\x19\x85"): return "jffs2"
    if head[:6] in (b"070701", b"070702", b"070707"): return "cpio"
    if head[1080:1082] == b"\x53\xef": return "ext"
    if head[:2] == b"\x1f\x8b": return "gzip"
    if head[:6] == b"\xfd7zXZ\x00": return "xz"
    if head[:3] == b"BZh": return "bzip2"
    return None

def copy_limited(source, target):
    count = 0
    with target.open("wb") as out:
        while block := source.read(1024 * 1024):
            count += len(block)
            if count > MAX_BYTES:
                raise ValueError("expanded_size_limit")
            out.write(block)

def scan_offsets(path):
    # Binwalk signatures supplement direct headers, including vendor prefixes.
    proc = subprocess.run(["/usr/bin/binwalk", "--signature", str(path)],
                          capture_output=True, timeout=30, check=False)
    if proc.returncode:
        raise ValueError("binwalk_failed")
    offsets = []
    for line in proc.stdout.decode(errors="replace").splitlines():
        match = re.match(r"\s*(\d+)\s+0x[0-9a-fA-F]+\s+(.+)", line)
        if match and any(k in match[2].lower() for k in
                         ["squashfs", "cramfs", "jffs2", "ubifs", "ubi erase", "cpio", "ext2", "ext3", "ext4", "gzip", "xz compressed", "bzip2"]):
            offsets.append(int(match[1]))
            if len(offsets) > MAX_CANDIDATES:
                raise ValueError("candidate_limit")
    return sorted(set(offsets))

def unpack(image: Path, scratch: Path):
    root = scratch / "rootfs"
    root.mkdir()
    pending = [(image, 0)]
    seen = set()
    successes, attempts, special_entries = [], [], []
    candidate_count = 0
    while pending:
        candidate, depth = pending.pop(0)
        candidate_count += 1
        if candidate_count > MAX_CANDIDATES or depth > 8:
            raise ValueError("extraction_depth_or_candidate_limit")
        with candidate.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest in seen: continue
        seen.add(digest)
        fmt = kind(candidate)
        if fmt in {"gzip", "xz", "bzip2"}:
            target = scratch / ("expanded-" + str(candidate_count))
            opener = {"gzip": gzip.open, "xz": lzma.open, "bzip2": bz2.open}[fmt]
            try:
                with opener(candidate, "rb") as source:
                    copy_limited(source, target)
                pending.append((target, depth + 1))
                attempts.append({"format": fmt, "status": "decompressed"})
            except (OSError, EOFError, ValueError, lzma.LZMAError):
                attempts.append({"format": fmt, "status": "failed"})
            continue
        if fmt:
            partition = root / ("partition-" + str(len(successes)))
            partition.mkdir()
            commands = {
                "squashfs": ["unsquashfs", "-no-progress", "-d", str(partition), str(candidate)],
                "cramfs": ["fsck.cramfs", "--extract=" + str(partition), str(candidate)],
                "ubifs": ["ubireader_extract_files", "-o", str(partition), str(candidate)],
                "jffs2": ["jefferson", "-d", str(partition), str(candidate)],
                "cpio": ["bsdtar", "--no-same-owner", "--no-same-permissions", "-xf", str(candidate), "-C", str(partition)],
                "ext": ["debugfs", "-R", "rdump / " + str(partition), str(candidate)],
            }
            try:
                if fmt in {"cramfs", "jffs2"}:
                    partition.rmdir()  # These extractors require a nonexistent destination.
                if fmt == "squashfs":
                    listing = subprocess.run(["unsquashfs", "-lln", str(candidate)], capture_output=True, timeout=30, check=True)
                    excluded = []
                    for line in listing.stdout.decode(errors="strict").splitlines():
                        if line and line[0] in "cbps":
                            match = re.match(r"^([cbps])\S*\s+\d+/\d+\s+(.+?)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+squashfs-root/(.+)$", line)
                            if not match:
                                raise ValueError("unparseable_special_inode")
                            relative = match[3]
                            if "\n" in relative or any(x in {"..", "."} for x in Path(relative).parts):
                                raise ValueError("unsafe_inode_path")
                            excluded.append(relative)
                            special_entries.append({"path": "/" + relative, "type": {"c":"character_device", "b":"block_device", "p":"fifo", "s":"socket"}[match[1]], "size": 0, "hash": None, "device": match[2].strip(), "materialized": False, "partition": partition.name})
                    commands[fmt][1:1] = ["-processors", "1"]
                    if excluded:
                        exclusion = scratch / (partition.name + "-excluded")
                        exclusion.write_text("\n".join(excluded) + "\n")
                        commands[fmt][1:1] = ["-exclude-file", str(exclusion), "-no-wildcards"]
                run_tool(commands[fmt])
                if not any(partition.iterdir()):
                    raise ValueError("empty_extraction")
                successes.append({"format": fmt, "partition": partition.name})
                attempts.append({"format": fmt, "status": "extracted"})
            except (ValueError, subprocess.TimeoutExpired):
                shutil.rmtree(partition, ignore_errors=True)
                attempts.append({"format": fmt, "status": "failed"})
            # A recognized filesystem is not recursively re-carved from itself.
            continue
        for offset in scan_offsets(candidate):
            if offset <= 0 or offset >= candidate.stat().st_size: continue
            target = scratch / ("carved-" + str(candidate_count) + "-" + str(offset))
            with candidate.open("rb") as source:
                source.seek(offset)
                copy_limited(source, target)
            if kind(target):
                pending.append((target, depth + 1))
    if not successes:
        return root, {"status": "unsupported", "attempts": attempts, "filesystems": []}
    # A single filesystem exposes paths relative to its own root.
    selected = root / successes[0]["partition"] if len(successes) == 1 else root
    partial = any(x["status"] == "failed" for x in attempts)
    return selected, {"status": "partial" if partial else "extracted",
                      "attempts": attempts, "filesystems": successes, "special_entries": special_entries}
