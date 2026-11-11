# Development environment inspection

Read-only inspection on 2026-10-19 (Asia/Kolkata). Raw commands, outputs, return codes and PRD hash: `../evidence/planning/environment.json`.

| Item | Observed |
| --- | --- |
| OS | Ubuntu 26.04.1 LTS (Resolute Raccoon) |
| CPU architecture | x86_64, little-endian host |
| CPU | 8 visible logical CPUs, Intel Core i5-13450HX |
| RAM | 7.2 GiB total; approximately 4.6 GiB available at inspection |
| Swap | 4.0 GiB, unused at inspection |
| Disk | Root/repository filesystem 87 GiB total, 16 GiB used, 68 GiB available |
| Docker Engine | 29.9.1; daemon read-only query succeeded |
| Docker Compose | v5.6.0 |
| Docker controls reported | cgroup v2; AppArmor, seccomp and cgroup namespaces |
| Git | 2.53.0 |
| System Python | /usr/bin/python3 → Python 3.14.4; python3.14 present; python3.11/3.12/3.13 not on PATH |
| KVM device | /dev/kvm absent; no usable KVM acceleration established |
| Virtualization | systemd-detect-virt: oracle; vboxguest loaded; lscpu reports KVM hypervisor CPUID. These mixed signals are recorded, not resolved by assumption. |
| Git state | Existing repository on unborn master, no commits; supplied files initially untracked; no configured user.name/email observed. |
| Repository | /home/ubunt/projects/firmwarex; distinct from projectless chat directory |

This was environment inspection, not containment validation. No packages installed, services started, images pulled, firmware executed, virtualization settings changed or system Python modified. Docker-reported security features do not prove job profiles enforce them.

Use QEMU TCG/software emulation as the supported baseline. Optional future KVM acceleration must not become an acceptance prerequisite. With limited RAM, start with one heavy analysis job at a time; concrete quotas/admission limits will be measured and pinned during implementation. Keep control-plane capacity reserved.

The existing empty `REQUREMENTS.md` is misspelled; leave it untouched and use canonical `REQUIREMENTS.md`. Existing docs were empty. No application implementation was present.
