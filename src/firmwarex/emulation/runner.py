"""Runs in a network-none container; service clients share its loopback namespace."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

EMULATORS = {"MIPS":"qemu-mips", "MIPSEL":"qemu-mipsel", "ARM32":"qemu-arm", "ARM64":"qemu-aarch64", "x86_64":"qemu-x86_64"}

def resolve(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("invalid_binary_path")
    return path

def command(request, root):
    arch = request["architecture"]
    if arch not in EMULATORS:
        raise ValueError("unsupported_architecture")
    binary = resolve(root, request["binary"])
    if hashlib.sha256(binary.read_bytes()).hexdigest() != request["sha256"]:
        raise ValueError("input_hash_mismatch")
    args = request.get("args", [])
    if not isinstance(args,list) or len(args)>32 or any(not isinstance(x,str) or len(x)>1024 for x in args):
        raise ValueError("invalid_arguments")
    # Linux noexec scratch forbids executable mmap even through QEMU. Only an
    # already hash-verified executable is copied to the bounded execution mount.
    if str(binary).startswith('/scratch/'):
        import shutil
        staged=Path('/guest')/request['sha256']
        if not staged.exists():shutil.copyfile(binary,staged);staged.chmod(0o500)
        if staged.is_symlink() or hashlib.sha256(staged.read_bytes()).hexdigest()!=request["sha256"]:raise ValueError("staged_hash_mismatch")
        binary=staged
    return [EMULATORS[arch], "-L", str(root), str(binary), *args]

def probe(protocol, port):
    if protocol == "upnp":
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.sendto(b'M-SEARCH * HTTP/1.1\r\nMAN: "ssdp:discover"\r\n\r\n',("127.0.0.1",port))
            response=sock.recv(4096)
            assert response.startswith(b"HTTP/1.1 200")
    else:
        with socket.create_connection(("127.0.0.1",port),timeout=2) as sock:
            payload = b"GET / HTTP/1.0\r\n\r\n" if protocol=="http" else bytes.fromhex("100f00044d5154540402003c0003667778")
            sock.sendall(payload)
            response=sock.recv(4096)
            assert response.startswith(b"HTTP/1.0 200") if protocol=="http" else response==bytes.fromhex("20020000")
    return {"protocol":protocol,"response_sha256":hashlib.sha256(response).hexdigest(),"bytes":len(response)}

def execute(request, root=None):
    root=Path("/input/rootfs") if root is None else root
    cmd=command(request,root)
    mode=request.get("mode","user")
    if mode=="system":
        # Only named machine profiles, never raw QEMU arguments.
        profiles={"ARM32":("qemu-system-arm","virt"),"ARM64":("qemu-system-aarch64","virt"),"MIPS":("qemu-system-mips","malta"),"MIPSEL":("qemu-system-mipsel","malta"),"x86_64":("qemu-system-x86_64","pc")}
        kernel=request.get("kernel")
        if not kernel:
            return {"status":"incomplete","reason":"kernel_profile_required","fallback":"user_mode","architecture":request["architecture"]}
        executable,machine=profiles[request["architecture"]]
        kernel_path=resolve(root,kernel)
        if hashlib.sha256(kernel_path.read_bytes()).hexdigest()!=request.get("kernel_sha256"):
            raise ValueError("kernel_hash_mismatch")
        cmd=[executable,"-machine",machine,"-accel","tcg","-m","128","-display","none","-monitor","none","-serial","file:/scratch/serial","-nic","none","-no-reboot","-kernel",str(kernel_path)]
    deadline=min(int(request.get("timeout_seconds",10)),60)
    if deadline<1: raise ValueError("invalid_timeout")
    if mode=="service":
        protocol=request["protocol"]
        if protocol not in {"http","upnp","mqtt"}:raise ValueError("unsupported_protocol")
        proc=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={"PATH":os.environ["PATH"],"HOME":"/tmp"})
        try:
            end=time.monotonic()+deadline
            while True:
                try: result=probe(protocol,18080);break
                except (OSError,AssertionError):
                    if proc.poll() is not None or time.monotonic()>end:raise TimeoutError("service_unavailable")
                    time.sleep(.05)
            return {"status":"completed","architecture":request["architecture"],"network":"job_private_loopback","probe":result}
        finally:
            if proc.poll() is None:proc.kill()
            proc.wait()
    if mode not in {"user","system"}:raise ValueError("unsupported_mode")
    try:
        with open("/scratch/stdout","wb") as out,open("/scratch/stderr","wb") as err:
            done=subprocess.run(cmd,stdout=out,stderr=err,timeout=deadline,env={"PATH":os.environ["PATH"],"HOME":"/tmp"},check=False)
        output=Path("/scratch/stdout").read_bytes()
        return {"status":"completed" if done.returncode==0 else "incomplete","architecture":request["architecture"],"mode":mode,"returncode":done.returncode,"stdout_sha256":hashlib.sha256(output).hexdigest(),"stdout_bytes":len(output),"fallback":"user_mode" if mode=="system" and done.returncode else None}
    except subprocess.TimeoutExpired:
        console=Path("/scratch/serial").read_bytes() if mode=="system" and Path("/scratch/serial").exists() else b""
        return {"console_sha256":hashlib.sha256(console).hexdigest(),"console_bytes":len(console),"status":"incomplete","reason":"emulator_timeout","mode":mode,"fallback":"user_mode" if mode=="system" else None}

def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024))
    os.umask(0o077)
    try:
        request=json.loads(Path("/input/request.json").read_text())
        result=execute(request)
    except Exception as error:
        result={"status":"failed","error_type":type(error).__name__}
    result["schema_version"]=1
    Path("/output/result.json").write_text(json.dumps(result))
if __name__=="__main__":main()
