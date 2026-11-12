"""Content-free output policy: preserve structure, pseudonymize unreviewed names."""
from firmwarex.scanners.secrets import fingerprint
from firmwarex.findings import FINDING_ENUMS
SAFE_COMPONENTS={'bin','sbin','usr','lib','lib64','etc','var','tmp','www','home','root','dev','proc','sys','opt','run','boot','mnt','media','share','init.d','taint-demo','service-probe','controlled.conf'}

def safe_path(path,salt):
    return '/'+'/'.join(part if part in SAFE_COMPONENTS or re.fullmatch(r'redacted-[a-f0-9]{16}',part) else 'redacted-'+fingerprint(part.encode('utf-8',errors='surrogateescape'),salt)[:16] for part in str(path).split('/') if part)

def sanitize_inventory(files,binaries,errors,salt):
    for item in files+binaries+errors:
        item['path']=safe_path(item['path'],salt)
        if 'device' in item:item['device']='redacted-device-metadata'
        if 'architecture' in item and item['architecture'] not in {'ARM32','ARM64','MIPS','MIPSEL','x86_64','x86'}:item['architecture']='unsupported'
    return files,binaries,errors

# Output is a typed diagnostic document, not an arbitrary firmware text channel.
# Unknown fields/strings are fingerprinted even if scanners did not recognize them.
import re
SAFE_KEYS=set('''CapDrop Memory MemorySwap NanoCpus NetworkMode PidsLimit Privileged ReadonlyRootfs SecurityOpt address aggregation_temporality alternative_paths analyses analysis_scope architecture architecture_inheritance args attempts attributes authorization banned_functions binaries binary binary_count bits bits_per_byte bucket_counts budgets byte_length byte_offset bytes bytes_scanned call_path category condition condition_satisfiable confidence constant count cpu_seconds crash_state cwe data data_points depth description detected_at edges elf_type emulation end_ns endianness entropy errors error_code error_type evidence evidence_ref executions exemplars exit_code explicit_bounds extract extraction fallback fault_address files files_scanned files_skipped filesystems filtered_attributes finding_count findings fingerprint firmware_id format fortify function functions graphs hash heuristic id image_id incomplete invocation_proven is_monotonic job.id job_id jobs kind limitations limits max memory_mb merge merged method metrics min mode name network network_mode nodes nodes_per_function normalize nx observability offset op outcome overflow_offset overflow_proven parent_span_id partition path paths peak_states pie probe profile protocol pruned raw_reveal rax rbp rdi rdx read_only reason reasons redacted registers relro resource resource_metrics response_sha256 result returncode rip risk_rating rsi rsp rule safety sandbox schema_url schema_version scope scope_metrics seconds secrets_crypto service.instance.id service.name sha256 sink size source source_bytes sources span_id spans special_entries stack_canary stack_hash stage stages start_ns start_time_unix_nano states static status stdout_bytes stdout_sha256 steps stripped sum symbol symbolic tainted tainted_path target telemetry telemetry.sdk.language telemetry.sdk.name telemetry.sdk.version time_unix_nano trace_id type unit untrusted_execution user value version vulnerability_id wall_seconds wx_segments control_observability trace_parent materialized device code parameters artifacts timeout_seconds timed_out killed oom_killed cleanup_removed return_code eip esp ebp pc sp r0 r1 r2 r3 r4 r5 r6 r7 a0 a1 a2 a3 v0 v1 ra fp'''.split())
SAFE_TEXT=set('''directory file symlink special character_device block_device fifo socket ARM32 ARM64 MIPS MIPSEL x86 x86_64 little big ET_EXEC ET_DYN ET_REL ET_CORE full partial none unsupported strcpy strcat gets sprintf memcpy system popen memory_corruption hardcoded_secret weak_crypto missing_mitigation command_injection low medium high critical informational heuristic probable confirmed new reviewed false_positive fixed complete completed incomplete finished failed blocked queued running static_complete extracted user system job_private_loopback http upnp mqtt exact_controlled_image_registry integrated_gated static_only squashfs cramfs jffs2 ubifs ext ext2 ext3 ext4 cpio gzip xz bzip2 lzma lz4 zstd tar extract static emulation symbolic secrets_crypto normalize pipeline upload queue_wait sandbox_execution persistence abandoned_job_recovery python opentelemetry firmwarex-analysis firmwarex.pipeline firmwarex.stage.completed firmwarex.stage.duration s ALL no-new-privileges:true blocked_pending_mentor_approval disabled main _start redacted redacted-device-metadata mentor_signoff_required controlled_fixture_gate sandbox_exit invalid_output invalid_schema launcher_failed missing_result static_runner_failed wall_quota cpu_quota memory_quota result_persistence_failed dispatcher_lost pipeline_failed report_size_limit malformed_elf time_budget state_budget path_budget depth_budget step_budget memory_budget source_limit no_candidates exhausted bounded_stopped UNSET OK ERROR TimeoutError ValueError RuntimeError OSError MemoryError FileNotFoundError'''.split())
SAFE_TEXT.update({
 'stage_error','graph_error',
 'Missing symbols may conceal canary/FORTIFY use; PIE does not prove runtime ASLR.',
 'angr CFGFast','single known image architecture; ambiguous non-ELF files skipped',
 'Source models use bounded printable bytes, not exhaustive inputs.',
 'Exploration stops at candidate sink violations; bounded safe copies preserve taint.',
 'Stack bounds require supported DWARF x86_64 frame-pointer ABI.',
 'No concrete command or exploit input is generated.','',
})
SAFE_KEYS.add('output_limit_bytes')
SAFE_KEYS.update({'console_sha256', 'console_bytes', 'bytes_before_denial', 'files_before_denial', 'checks', 'interfaces', 'uid', 'mount_return', 'mount_errno', 'socket_present', 'host_connect_errno', 'udp_2', 'udp_10'})
SAFE_TEXT.update({'lo', 'kernel_profile_required', 'user_mode', 'emulator_timeout'})
SAFE_KEYS.update({'protocol', 'seed', 'seed_index', 'retained_indices', 'original_length',
                  'minimization_attempts', 'replay_verified', 'replays', 'runs', 'fuzz',
                  'snapshots', 'restores', 'state_sha256', 'advanced', 'restored', 'snapshot'})
SAFE_TEXT.update({'crash', 'fuzz', 'snapshots', 'snapshot_error', 'fuzz_budget', 'trial_timeout', 'controlled_protocol_null_write'})

SAFE_KEYS.update({'observations','entropy_candidates','certificates','candidate_count','selected_count','target_limit','vendor_analysis'})
SAFE_KEYS.update({'coverage','profile_status','engine_status','engine_reasons','entry_evidence','input_calls','sink_calls','start_context','argc','argv0','environment','working_directory','stdin_eof','symbolic_environment_prefixes','input_scope','objective','source_prefix','matched_finding_ids','binary_sha256','proven_safe_copies','terminal_returns'})
SAFE_KEYS.update({'startup','request','response','cleanup'})
SAFE_KEYS.update({'cve','firmware_sha256','input_sha256','input_bytes','normal_request','service_exit_code',
                  'service_signal','service_configuration','package_version','fixed_release',
                  'upstream_fix','started_time_unix_nano','finished_time_unix_nano','outcome',
                  'expected_outcome'})
SAFE_KEYS.add('symbolic_environment')
SAFE_TEXT.update({'named_environment','CONTENT_TYPE','/','multipart_header_empty_body','profiled_input','symbolic','unsupported'})
SAFE_TEXT.add('profile_memory_fault_requires_validation')
SAFE_TEXT.update({'sampled_profiles','http_harness_verified','applet_verified','selected_profiles_only','selected_profiles_complete','profile_binary_mismatch','profile_objective_only','selected_profile_objective_reached','not_applicable','symbolic_profile_only','no_symbolic_profile','modeled_getenv_any_key','not_modeled','sandboxed_execution','/usr/libexec/cgi-upload','pending','not_sent','not_checked','exited','listening','sent','http_200_marker_verified','unexpected','process_reaped'})
SAFE_TEXT.add('symbolic_null_write')
SAFE_TEXT.update({'mentor_authorized','sampled_help_mode','bounded_sample','startup_exit','help_mode_only','execution_root_budget','program_entry_limited_models','engine_error_SimSegfaultException','vendor_analysis','analysis_error','symbolic_allocation_truncated','symbolic_allocation_budget'})
SAFE_TEXT.update({'cve_2019_19945_runtime_reproduction','CVE-2019-19945',
                  'openwrt_18_06_5_cve_2019_19945','openwrt_18_06_6_patched_control',
                  'crash_reproduced','crash_not_reproduced','patched_control_survived',
                  'private_loopback_cgi_synthetic_handler','SIGABRT','runtime_profile_only',
                  '2018-11-28-cdfc902a-3','2020-03-13-5e9c23c6',
                  '5f9ae5738372aaa3a6be2f0a278933563d3f191a','unexpected_service_exit'})
SAFE_TEXT.add('client_poll_post_data')

def sanitize_output(value,salt,field=None):
    """Idempotent, fail-closed text boundary for current and historical diagnostics.

    Caller-supplied display names/provenance are separate user metadata. Raw input
    remains restricted. Numeric metadata and typed hashes/addresses are retained;
    this does not claim to eliminate covert encoding in structured numeric data.
    """
    from firmwarex.diagnostic_vocabulary import WORDS
    if isinstance(value,dict):
        result={}
        for key,child in value.items():
            if key in SAFE_KEYS or re.fullmatch(r'evidence:[a-f0-9]{64}|redacted-[a-f0-9]{16}',key):outkey=key
            elif key.startswith('/'):outkey=safe_path(key,salt)
            else:outkey='redacted-'+fingerprint(key.encode(),salt)[:16]
            result[outkey]=sanitize_output(child,salt,key)
        return result
    if isinstance(value,list):return [sanitize_output(child,salt,field) for child in value]
    if not isinstance(value,str):return value
    if value in FINDING_ENUMS.get(field, ()):return value
    if value in SAFE_TEXT or value in WORDS or re.fullmatch(r'redacted-[a-f0-9]{16}',value):return value
    if field in {'path','binary'}:return safe_path(value,salt)
    patterns={
      'cwe':r'CWE-[0-9]+', 'partition':r'partition-[0-9]+',
      'source':r'0x[0-9a-f]+|(?:fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+)(?:,fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+)*',
      'sources':r'fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+',
      'symbol':r'fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+',
      'evidence_ref':r'evidence:[a-f0-9]{64}', 'image_id':r'sha256:[a-f0-9]{64}',
      'name':r'function_0x[0-9a-f]+', 'detected_at':r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+Z-]+',
      'version':r'[0-9]+(?:\.[0-9]+){1,3}', 'schema_version':r'[0-9]+(?:\.[0-9]+){1,3}',
      'telemetry.sdk.version':r'[0-9]+(?:\.[0-9]+){1,3}', 'user':r'[0-9]+:[0-9]+'}
    for key in ['firmware_id','job_id','job.id','vulnerability_id','service.instance.id','matched_finding_ids']:patterns[key]=r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}'
    for key in ['sha256','binary_sha256','firmware_sha256','input_sha256','hash','fingerprint','stdout_sha256','console_sha256','response_sha256','stack_hash','state_sha256']:patterns[key]=r'[a-f0-9]{64}'
    patterns['source_prefix']=r'fwx_(?:cgi_stdin|cgi_query|environment|network)_'
    for key in ['trace_id']:patterns[key]=r'[a-f0-9]{32}'
    for key in ['span_id','parent_span_id']:patterns[key]=r'[a-f0-9]{16}'
    for key in ['address','id','source','target','tainted_path','call_path','alternative_paths','fault_address','wx_segments','rax','rbp','rdi','rdx','rip','rsi','rsp','eip','esp','ebp','pc','sp']:patterns[key]=patterns.get(key,r'0x[0-9a-f]+')
    if field in patterns and re.fullmatch(patterns[field],value):return value
    return 'redacted-'+fingerprint(value.encode('utf-8',errors='surrogateescape'),salt)[:16]
