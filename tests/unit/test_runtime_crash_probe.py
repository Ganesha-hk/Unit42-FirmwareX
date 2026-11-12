"""Exercise probe outcomes without running firmware or depending on the clock."""
import signal
from uuid import uuid4

import pytest

import firmwarex.vendor_analysis as vendor


@pytest.mark.parametrize(('mode', 'expected', 'finding'), [
    ('startup_failure', 'startup_exit', False),
    ('timeout', 'time_budget', False),
    ('abort', 'crash_reproduced', True),
    ('exit_134', 'unexpected_service_exit', False),
    ('survives', 'crash_not_reproduced', False),
    ('patched', 'patched_control_survived', False),
])
def test_runtime_probe_outcomes(monkeypatch, tmp_path, mode, expected, finding):
    binary=tmp_path/'uhttpd'; binary.write_bytes(b'controlled binary')
    original_path=vendor.Path
    monkeypatch.setattr(vendor, 'Path', lambda path: tmp_path/'web' if path == '/guest/cve-2019-19945-web' else original_path(path))
    ticks=iter(range(1000))
    monkeypatch.setattr(vendor.time, 'monotonic', lambda: next(ticks)/10)
    monkeypatch.setattr(vendor.time, 'sleep', lambda _: None)
    monkeypatch.setattr(vendor.os, 'killpg', lambda *args: None)
    class Process:
        pid=987654
        returncode=1 if mode == 'startup_failure' else None
        def poll(self): return self.returncode
        def wait(self): self.returncode=self.returncode if self.returncode is not None else -signal.SIGKILL; return self.returncode
    proc=Process()
    monkeypatch.setattr(vendor.subprocess, 'Popen', lambda *args, **kwargs: proc)
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def sendall(self, data):
            if data.startswith(b'POST'):
                if mode == 'abort': proc.returncode=-signal.SIGABRT
                if mode == 'exit_134': proc.returncode=134
        def recv(self, size):
            if hasattr(self, 'sent'): return b''
            self.sent=True
            return b'HTTP/1.0 200 OK\r\n\r\nfirmwarex-cve-control\n'
    def connect(*args, **kwargs):
        if mode == 'timeout': raise OSError('unavailable')
        return Socket()
    monkeypatch.setattr(vendor.socket, 'create_connection', connect)
    profile=vendor.OPENWRT_18066_PROFILE if mode == 'patched' else vendor.OPENWRT_18065_PROFILE
    result=vendor.cve_2019_19945_probe(['controlled'],profile,str(uuid4()),binary,'x86_64','a'*64,b's'*32)
    assert result['reason'] == expected
    assert ('finding' in result) is finding
    assert result['cleanup'] == 'process_reaped'
    if mode in {'survives','patched'}: assert result['service_exit_code'] is None
    if finding:
        assert result['finding']['confidence']=='probable'
        evidence=next(iter(result['evidence'].values()))
        assert evidence['normal_request']=='http_200_marker_verified'
        assert evidence['service_signal']=='SIGABRT'
        assert evidence['overflow_proven'] is False


def test_runtime_binary_checksum_mismatch_is_not_selected(tmp_path):
    binary=tmp_path/'usr/sbin/uhttpd'; binary.parent.mkdir(parents=True); binary.write_bytes(b'changed')
    selected,_=vendor.openwrt_targets(tmp_path,[{'path':'/usr/sbin/uhttpd','architecture':'x86_64'}],vendor.OPENWRT_18065_PROFILE['binaries'],vendor.OPENWRT_18065_PROFILE['binaries'])
    assert selected == []
