# Planning decisions — 2026-10-19

These are implementation proposals, not deployed choices. Authoritative rationale and sources: implementation-plan.md.

| Decision | Rationale | Verification still required |
| --- | --- | --- |
| Isolated CPython 3.12, separate control/analysis environments | Supported by chosen angr metadata; preserve host Python 3.14.4 | Full dependency resolution, native imports and controlled analysis smoke checks |
| Initial candidate angr 10.0.4.post1 with declared matched dependencies | Actual PyPI metadata saved; avoid mixing family generations | Build/install and runtime behavior, complete hash lock |
| Docker Compose, FastAPI, Celery, Redis, PostgreSQL | Fits PRD layers and single VM | Clean deployment, queue/persistence integration |
| Trusted dispatcher outside no-egress one-shot sandboxes | Broker/DB access must not open worker egress | All profiles' route/packet/host-denial tests |
| QEMU software TCG baseline | /dev/kvm absent; cross-architecture execution still required | Target fixture execution and performance |
| Native Binwalk/Ghidra/QEMU tools isolated by image/adapters | Avoid Python/native-tool dependency collisions | Per-tool version pinning and all format/CFG/emulation contracts |
| Ghidra CFG export, bounded Unicorn adapter; angr primary symbolic engine | Architecture/reference-tool coverage without redundant engines | Real adapters, CFG UI and analysis tests |
| REST API and lightweight TypeScript/Vite/Cytoscape UI | PRD offers REST/gRPC choice; required interactive CFG | Exact endpoint and browser acceptance |
| Single heavy job initially | 7.2 GiB RAM; reserve API capacity | Load tests, measured quotas/back-pressure |
| Immutable ID index, explicit priority inference | Preserve authoritative PRD with honest interpretation | Future changes reviewed against source; no renumbering |

No dependency version/digest not verified in metadata is represented as a final lock. This paragraph records the initial planning state; later milestones below supersede it. No sandbox sign-off exists.

## Task 2 implementation decisions

- Docker Python 3.12.15 pinned by digest; control and analysis locks installed. angr 10.0.4.post1/Unicorn 2.1.4 passed actual controlled smoke checks.
- Extraction uses Debian snapshot-pinned Binwalk 2.3.4 instead of proposed Rust v3. The PRD requires Binwalk capability, not a version; packaged signatures plus dedicated extraction adapters passed six-format tests. Python 3.11 bundled inside that native-tool image runs the distro Binwalk CLI only; application/runtime remains 3.12 and host Python unchanged.
- Native apt package universe pinned to Debian snapshot 20261001T000000Z; installed versions recorded. Analysis/extraction platform locks preserve exact selected wheel hashes; full pip-tools locks also retained.
- API has separate ingress network; the control network is internal. Offline analysis uses network none. Static device inodes remain inventory metadata instead of materialized device nodes.
- User authorized local author Ganesha HK <ganeshahk806@gmail.com> and origin https://github.com/Ganesha-hk/Unit42-FirmwareX.git. No push, publication, PR creation, merge or external mutation without asking first.

## Task 3 — private-loopback QEMU services

Use one network-none namespace per emulation job for both guest service and probe. This removes the need for a routed bridge and supports HTTP, SSDP/UPnP and MQTT without host exposure. Do not introduce network-enabled QEMU profiles merely to make services reachable. Full-system profiles use TCG (no KVM required), no NIC, named machines and an explicit incomplete/fallback result. Only separately hash-registered controlled binaries/rootfs content are executable before mentor review. Minimal read-only NVRAM shims and QEMU generic peripheral models do not imply vendor firmware compatibility.

## Task 4 — bounded analysis and finding boundary

Keep the pinned isolated angr runtime and adapt to angr 10's bundled claripy API. Track source-variable dependencies through real symbolic execution; hook commands without invoking them. Use observed ELF/DWARF/modeled allocation bounds, never guessed overflow offsets. Label candidates probable or heuristic and preserve unsupported/budget incompleteness. Fingerprint raw scanner content with firmware-private random HMAC salt; persist only normalized findings and structurally validated diagnostic evidence. Disable raw reveal until an authorized, audited workflow is implemented. Integrate these components into the queued pipeline and universal redaction in the next milestone, preserving all unmet PRD requirements.

## Task 5 — one offline pipeline and local dashboard

Keep extraction, QEMU, angr and scanning in one no-egress container to avoid exporting raw rootfs content between stages. Use an exact-image controlled execution registry. Retain noexec scratch and introduce a bounded 32 MiB executable /guest tmpfs only for hash-verified targets; explicit mentor/PR scrutiny remains required. Use local OpenTelemetry SDK exporters and buildless HTML/CSS/JavaScript with real angr CFG data instead of the proposed Vite/Cytoscape stack; those specific frontend tools were not normative. Unknown path components are salted pseudonyms. The additional static findings remain heuristic, with no invented overflow state.

CWE interpretation checked against primary definitions: [CWE-676](https://cwe.mitre.org/data/definitions/676.html) and [CWE-242](https://cwe.mitre.org/data/definitions/242.html). A symbol alone does not prove invocation; evidence explicitly records invocation_proven=false and overflow_proven=false. The Appendix B reference mappings remain unchanged, and CWE-1277 is never used merely for absent ELF mitigations.
