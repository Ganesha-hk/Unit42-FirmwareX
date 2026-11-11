"""Trusted launcher. This module never runs inside an analysis container."""
import json
import io
import os
import tarfile
import time
from pathlib import Path
from uuid import UUID
import docker
from firmwarex.output_policy import sanitize_output

MAX_REPORT_BYTES = 32 * 1024 * 1024
OUTPUT_BYTES = 40 * 1024 * 1024
# Keep tmpfs mounted after the workload exits so the trusted controller can
# freeze it and copy only the bounded regular result file. No host write mount.
SUPERVISOR = '''import os,subprocess,sys,time
from pathlib import Path
code=subprocess.call(sys.argv[1:])
Path('/output/.fwx-exit.tmp').write_text(str(code))
os.replace('/output/.fwx-exit.tmp','/output/.fwx-exit')
while True: time.sleep(60)
'''


def read_container_file(container, path, limit):
    """Never extract a guest-controlled tar archive onto the host."""
    stream, metadata = container.get_archive(path)
    try:
        if metadata.get('size', limit + 1) > limit:
            raise ValueError('invalid_output')
        archive = bytearray()
        for chunk in stream:
            if len(archive) + len(chunk) > limit + 65536:
                raise ValueError('invalid_output')
            archive.extend(chunk)
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
            members = tar.getmembers()
            if len(members) != 1 or not members[0].isreg() or members[0].size > limit:
                raise ValueError('invalid_output')
            with tar.extractfile(members[0]) as file:
                return file.read(limit + 1)
    finally:
        close = getattr(stream, 'close', None)
        if close:
            close()


def sanitize_sandbox_result(result, salt):
    """Validate and sanitize one decoded guest report before it is persisted."""
    if not isinstance(result, dict) or result.get("schema_version") != 1:
        raise ValueError("invalid schema")
    if not isinstance(salt, bytes) or len(salt) < 32:
        raise ValueError("invalid salt")
    safe = sanitize_output(result, salt)
    if safe.get("schema_version") != 1:
        raise ValueError("invalid sanitized schema")
    encoded = json.dumps(safe, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("output too large")
    return safe, encoded


def output_salt(input_dir):
    """Reuse a firmware salt, or create a private salt for standalone jobs."""
    path = input_dir / 'fingerprint-salt'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        import stat
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('invalid salt file')
            salt = stream.read(33)
    else:
        salt = os.urandom(32)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(salt)
    if len(salt) != 32:
        raise ValueError('invalid salt')
    return salt

def launch(job_id, config, scope="static"):
    if scope not in {"static", "emulation", "analysis", "pipeline"}: raise ValueError("invalid sandbox scope")
    UUID(job_id)
    local = config.storage / "jobs" / job_id
    host = Path(config.host_storage) / "jobs" / job_id
    salt = output_salt(local / 'input')
    output = local / "output"
    output.mkdir(mode=0o700)
    os.chown(output, config.sandbox_uid, config.sandbox_gid)
    client = docker.from_env()
    container = None
    volume = None
    telemetry = {"network_mode": "none", "read_only": True, "reason": None}
    try:
        image_config = client.images.get(config.static_image).attrs['Config']
        workload = (image_config.get('Entrypoint') or []) + (image_config.get('Cmd') or [])
        if not workload:
            raise ValueError('missing workload')
        # Docker's archive API cannot read --tmpfs mounts. A local-driver
        # tmpfs volume has the same kernel quota and supports bounded copying.
        volume = client.volumes.create(
            name='firmwarex-output-' + job_id, driver='local',
            driver_opts={'type': 'tmpfs', 'device': 'tmpfs',
                         'o': f'size={OUTPUT_BYTES},nr_inodes=1024,mode=0700,uid={config.sandbox_uid},gid={config.sandbox_gid},nosuid,nodev,noexec'},
            labels={'firmwarex.job_id': job_id, 'firmwarex.scope': scope},
        )
        container = client.containers.run(
            config.static_image, detach=True, network_mode="none",
            entrypoint=['python', '-c', SUPERVISOR], command=workload,
            user=f"{config.sandbox_uid}:{config.sandbox_gid}",
            read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit=config.job_memory_bytes, memswap_limit=config.job_memory_bytes,
            nano_cpus=1_000_000_000, pids_limit=64,
            environment={"FWX_CPU_SECONDS": str(config.job_cpu_seconds)},
            tmpfs={"/scratch": "rw,nosuid,nodev,noexec,size=536870912,mode=1777",
                   "/tmp": "rw,nosuid,nodev,noexec,size=33554432,mode=1777",
                   **({"/guest": "rw,nosuid,nodev,exec,size=33554432,mode=1777"} if scope=="pipeline" else {})},
            volumes={str(host / "input"): {"bind": "/input", "mode": "ro"},
                     volume.name: {'bind': '/output', 'mode': 'rw'}},
            labels={"firmwarex.job_id": job_id, "firmwarex.scope": scope},
            log_config=docker.types.LogConfig(type="none"),
            init=True,
        )
        container.reload()
        host_config = container.attrs["HostConfig"]
        telemetry["profile"] = {key: host_config.get(key) for key in (
            "NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "Privileged",
            "Memory", "MemorySwap", "NanoCpus", "PidsLimit")}
        telemetry["image_id"] = container.attrs["Image"]
        telemetry["user"] = container.attrs["Config"]["User"]
        started = time.monotonic()
        workload_exit = None
        while True:
            container.reload()
            if container.status in {"exited", "dead"}: break
            try:
                workload_exit = int(read_container_file(container, '/output/.fwx-exit', 32))
            except docker.errors.NotFound:
                pass
            else:
                container.pause()
                break
            elapsed = time.monotonic() - started
            stats = container.stats(stream=False, one_shot=True)
            used = stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0) / 1e9
            telemetry.update(wall_seconds=round(elapsed, 3), cpu_seconds=round(used, 3))
            if elapsed > config.job_wall_seconds or used > config.job_cpu_seconds:
                telemetry["reason"] = "wall_quota" if elapsed > config.job_wall_seconds else "cpu_quota"
                container.kill()
                container.wait(timeout=10)
                break
            time.sleep(0.2)
        telemetry["wall_seconds"] = round(time.monotonic() - started, 3)
        container.reload()
        state = container.attrs["State"]
        if state.get("OOMKilled"): telemetry["reason"] = "memory_quota"
        telemetry["exit_code"] = workload_exit if workload_exit is not None else state.get("ExitCode")
        telemetry['output_limit_bytes'] = OUTPUT_BYTES
        path = output / "result.json"
        if telemetry["reason"] or telemetry["exit_code"] != 0:
            return {"error_code": telemetry["reason"] or "sandbox_exit"}, telemetry
        try:
            encoded = read_container_file(container, '/output/result.json', MAX_REPORT_BYTES)
            result = json.loads(encoded)
        except (docker.errors.NotFound, ValueError, tarfile.TarError):
            return {"error_code": "invalid_output"}, telemetry
        # This is the last untrusted-to-trusted boundary.  Workers sanitize
        # their own reports as well, but that is defence in depth only: never
        # persist guest-provided JSON before applying the central policy here.
        # The dispatcher sees persistent job storage through ``local`` (/data).
        # ``host`` is only a Docker bind source and is not necessarily mounted
        # at that absolute path inside the dispatcher container.
        try:
            result, encoded = sanitize_sandbox_result(result, salt)
        except (OSError, ValueError, TypeError):
            return {"error_code": "invalid_output"}, telemetry
        # Only the centrally sanitized, bounded artifact crosses to durable
        # host storage.  Rename avoids a partially-written report on failure.
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(encoded)
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
        return result, telemetry
    finally:
        try:
            if container:
                container.remove(force=True, v=True)
        finally:
            try:
                if volume:
                    volume.remove()
            finally:
                client.close()


def cleanup_job(job_id):
    """Remove only containers carrying this validated FirmwareX job identity."""
    UUID(job_id)
    client = docker.from_env()
    try:
        for container in client.containers.list(all=True, filters={"label": ["firmwarex.job_id=" + job_id]}):
            if container.labels.get("firmwarex.scope") in {"static","emulation","analysis","pipeline"}:
                container.remove(force=True, v=True)
        for volume in client.volumes.list(filters={'label': ['firmwarex.job_id=' + job_id]}):
            if volume.attrs.get('Labels', {}).get('firmwarex.scope') in {'static','emulation','analysis','pipeline'}:
                volume.remove()
    finally:
        client.close()
