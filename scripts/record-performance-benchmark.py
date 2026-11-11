"""Historical benchmark script; use benchmark-real-report.py for current runs."""
raise SystemExit('Use python3 scripts/benchmark-real-report.py REPORT OUTPUT; this historical script summed overlapping spans.')
import json, platform
from pathlib import Path

root = Path(__file__).resolve().parents[1]
report_path = root / 'evidence/mentor-accuracy-2026-11-07/openwrt-demo/report.json'
report = json.loads(report_path.read_text())
job = report['jobs'][-1]
observability = job['result']['control_observability']
durations = {}
for resource in observability.get('metrics', {}).get('resource_metrics', []):
    for scope in resource.get('scope_metrics', []):
        for metric in scope.get('metrics', []):
            if metric.get('name') != 'firmwarex.stage.duration':
                continue
            for point in metric['data'].get('data_points', []):
                stage = point['attributes'].get('stage')
                durations[stage] = durations.get(stage, 0.0) + float(point.get('sum', 0.0))
record = {
    'status': 'partial_benchmark',
    'firmware_id': report['firmware_id'],
    'job_id': job['job_id'],
    'sha256': report['sha256'],
    'host': {'platform': platform.platform(), 'python': platform.python_version(), 'processor': platform.processor()},
    'configuration': {'image': 'firmwarex-pipeline:task5', 'mentor_authorized': True,
                      'network': 'none', 'symbolic_budgets': {'seconds_per_binary': 10, 'steps': 200, 'memory_mb': 512}},
    'stage_seconds': {key: round(value, 6) for key, value in sorted(durations.items())},
    'total_seconds': round(sum(durations.values()), 6),
    'stage_status': {key: value.get('status') for key, value in job['result']['stages'].items()},
    'acceptance': 'Not a passing KPI benchmark because emulation and symbolic stages are incomplete; records exact observed timing only.'
}
assert record['total_seconds'] < 1800
out = root / 'evidence/acceptance-2026-11-08/performance-benchmark.json'
out.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
