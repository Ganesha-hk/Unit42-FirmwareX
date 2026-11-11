"""QEMU state snapshots for hash-registered ARM fixtures, inside the sandbox.

Only fixed machine, memory address, disk and monitor commands are supported.
Snapshots remain in job-local scratch and never become downloadable raw state.
"""
import hashlib
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path


class Monitor:
    def __init__(self, path, process, deadline):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        while True:
            try:
                self.socket.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None or time.monotonic() > deadline:
                    self.socket.close()
                    raise TimeoutError('snapshot_startup')
                time.sleep(.02)
        self.file = self.socket.makefile('rwb')
        self.read()
        self.command('qmp_capabilities')

    def read(self):
        line = self.file.readline(65537)
        if not line or len(line) > 65536:
            raise ValueError('invalid_monitor_response')
        return json.loads(line)

    def command(self, name, arguments=None):
        self.file.write(json.dumps({'execute': name, 'arguments': arguments or {}}).encode() + b'\n')
        self.file.flush()
        for _ in range(32):
            response = self.read()
            if 'error' in response:
                raise ValueError('snapshot_command_failed')
            if 'return' in response:
                return response['return']
        raise ValueError('monitor_event_limit')

    def human(self, command):
        return self.command('human-monitor-command', {'command-line': command})

    def close(self):
        self.file.close()
        self.socket.close()


def validate_target(target, root, registry):
    if set(target) != {'binary', 'sha256', 'architecture'} or target['architecture'] != 'ARM32':
        raise PermissionError('snapshot_fixture_gate')
    registered = registry.get(target['sha256'])
    if not registered or registered['architecture'] != target['architecture'] or Path(target['binary']).name != registered['binary']:
        raise PermissionError('snapshot_fixture_gate')
    original = Path(root) / target['binary']
    path = original.resolve()
    if original.is_symlink() or not path.is_relative_to(Path(root).resolve()) or not path.is_file():
        raise PermissionError('snapshot_fixture_gate')
    if hashlib.sha256(path.read_bytes()).hexdigest() != target['sha256']:
        raise PermissionError('snapshot_fixture_gate')
    return path


def run(target, root, registry):
    kernel = validate_target(target, root, registry)
    with tempfile.TemporaryDirectory(prefix='snapshot-', dir='/scratch') as directory:
        folder = Path(directory)
        disk, monitor_path = folder/'state.qcow2', folder/'qmp.sock'
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(disk), '8M'],
                       check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        args = ['qemu-system-arm', '-machine', 'virt', '-accel', 'tcg', '-m', '128',
                '-display', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
                '-no-reboot', '-kernel', str(kernel), '-S',
                '-drive', f'file={disk},if=none,id=snapshot,format=qcow2',
                '-device', 'virtio-blk-device,drive=snapshot',
                '-qmp', f'unix:{monitor_path},server=on,wait=off']
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        monitor = None
        try:
            monitor = Monitor(monitor_path, process, time.monotonic()+5)
            def read_state():
                value = monitor.human('xp /1wx 0x40020000')
                match = re.search(r':\s*(0x[0-9a-fA-F]+)', value)
                if not match:
                    raise ValueError('snapshot_state_missing')
                return int(match[1], 16)
            monitor.command('cont'); time.sleep(.1); monitor.command('stop')
            before = read_state()
            if before == 0:
                raise ValueError('snapshot_guest_not_running')
            response = monitor.human('savevm controlled')
            if response.strip():
                raise ValueError('snapshot_save_failed')
            restores = []
            for _ in range(2):
                monitor.command('cont'); time.sleep(.1); monitor.command('stop')
                advanced = read_state()
                if monitor.human('loadvm controlled').strip():
                    raise ValueError('snapshot_restore_failed')
                restored = read_state()
                if advanced == before or restored != before:
                    raise ValueError('snapshot_state_mismatch')
                restores.append({'advanced': True, 'restored': True})
            return {'status': 'completed', 'architecture': 'ARM32', 'restores': restores,
                    'state_sha256': hashlib.sha256(before.to_bytes(4, 'little')).hexdigest()}
        finally:
            if monitor:
                monitor.close()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def main():
    import os
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o077)
    try:
        request = json.loads(Path('/input/request.json').read_text())
        registry = json.loads(Path('/app/snapshot-controlled.json').read_text())
        result = run(request['target'], Path('/input/rootfs'), registry)
    except Exception:
        result = {'status': 'incomplete', 'reason': 'snapshot_error'}
    Path('/output/result.json').write_text(json.dumps({'schema_version': 1, **result}))


if __name__ == '__main__':
    main()
