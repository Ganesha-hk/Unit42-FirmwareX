"""Offline entrypoint: fixed input path; never executes firmware binaries."""
import json
import os
import resource
from pathlib import Path
from firmwarex.extract import unpack, entropy
from firmwarex.inventory import inventory

def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024 * 1024, 512 * 1024 * 1024))
    # Per-process CPU bound complements launcher aggregate cgroup CPU accounting.
    cpu = int(os.environ.get("FWX_CPU_SECONDS", "120"))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    output = Path("/output/result.json")
    try:
        image = Path("/input/firmware.bin")
        ent = entropy(image)
        root, extraction = unpack(image, Path("/scratch"))
        files, binaries, errors = inventory(root)
        for special in extraction.get("special_entries", []):
            item = dict(special)
            partition = item.pop("partition")
            if len(extraction["filesystems"]) > 1:
                item["path"] = "/" + partition + item["path"]
            files.append(item)
        files.sort(key=lambda item: item["path"])
        result = {"schema_version": 1, "extraction": extraction, "entropy": ent,
                  "files": files, "binaries": binaries, "errors": errors,
                  "analysis_scope": "static_only"}
    except Exception as error:
        # Never leak tool diagnostics or attacker-provided strings.
        result = {"schema_version": 1, "error_code": "static_runner_failed",
                  "error_type": type(error).__name__}
    temp = output.with_suffix(".tmp")
    temp.write_text(json.dumps(result))
    temp.replace(output)

if __name__ == "__main__":
    main()
