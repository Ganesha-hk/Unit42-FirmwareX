"""Shared content-free diagnostic vocabulary; no database dependency."""
WORDS={'potentially_dangerous_function_symbol','strcpy','strcat','sprintf','gets','getenv','read','credential','private_key','certificate','high_entropy','security_weak_crypto','modeled_out_of_bounds_write','tainted_command_sink','tainted_format_sink','tainted_copy_unknown_object_bounds','symbolic_memory_fault','redacted','unmodeled','BVS','BVV','BoolV','Extract','Concat','And','Or','Not','If','UGE','ULE','UGT','ULT','SGE','SLE','SGT','SLT','ZeroExt','SignExt','__eq__','__ne__','__add__','__sub__','__mul__','__and__','__or__','__xor__','__lshift__','__rshift__','LShR','Reverse'}
KEYS={'function','invocation_proven','overflow_proven','rule','byte_offset','byte_length','fingerprint','redacted','heuristic','kind','sources','condition','condition_satisfiable','call_path','alternative_paths','symbol','bits','constant','op','args','truncated','symbolic'}
WORDS.update({'controlled_protocol_null_write', 'http', 'upnp', 'mqtt'})
WORDS.add('symbolic_null_write')
KEYS.update({'protocol', 'seed', 'seed_index', 'retained_indices', 'original_length',
             'minimization_attempts', 'replay_verified', 'replays'})
WORDS.update({'cve_2019_19945_runtime_reproduction', 'CVE-2019-19945',
              'openwrt_18_06_5_cve_2019_19945', 'openwrt_18_06_6_patched_control',
              'http_200_marker_verified', 'crash_reproduced', 'crash_not_reproduced',
              'patched_control_survived', 'private_loopback_cgi_synthetic_handler',
              'SIGABRT', 'process_reaped', 'runtime_profile_only',
              '2018-11-28-cdfc902a-3', '2020-03-13-5e9c23c6',
              '5f9ae5738372aaa3a6be2f0a278933563d3f191a'})
KEYS.update({'cve', 'firmware_sha256', 'binary_sha256', 'input_sha256', 'input_bytes',
             'normal_request', 'service_exit_code', 'service_signal', 'cleanup',
             'service_configuration', 'package_version', 'fixed_release',
             'upstream_fix', 'started_time_unix_nano', 'finished_time_unix_nano',
             'outcome', 'expected_outcome'})
