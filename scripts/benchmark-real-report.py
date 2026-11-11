"""Record non-overlapping wall times and actual scope from a fresh real report."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path

def measure(report):
    job = report['jobs'][-1]
    result = job['result']
    spans = result['observability']['spans']
    def span(name):
        selected = [row for row in spans if row['name'] == name]
        if len(selected) != 1:
            raise ValueError('Expected one timing span for ' + name)
        row = selected[0]
        if row['end_ns'] <= row['start_ns']:
            raise ValueError('Invalid span interval')
        return row
    static, vendor, pipeline = span('static'), span('vendor_analysis'), span('pipeline')
    # vendor_analysis contains the actual emulation and symbolic work; the
    # later symbolic span merely assigns results. Never sum nested spans.
    elapsed = (vendor['end_ns'] - static['start_ns']) / 1e9
    stage = result['stages']['symbolic']
    analyses = [a for a in stage['analyses'] if a.get('status') != 'not_applicable']
    passed = (job['status'] == 'complete' and result['stages']['static']['status'] == 'completed'
              and stage['status'] == 'completed' and bool(analyses)
              and all(a.get('status') == 'completed' and not a.get('reasons') for a in analyses)
              and 0 < elapsed < 1800)
    return {
        'result': 'PASS' if passed else 'FAIL', 'scope': 'selected_profiles_only',
        'firmware_id': report['firmware_id'], 'sha256': report['sha256'], 'job_id': job['job_id'],
        'measurement': 'Wall interval from static start to vendor_analysis end; includes selected emulation and symbolic work.',
        'interval_start_ns': static['start_ns'], 'interval_end_ns': vendor['end_ns'],
        'static_plus_selected_analysis_seconds': elapsed,
        'pipeline_seconds': (pipeline['end_ns'] - pipeline['start_ns']) / 1e9,
        'threshold_seconds': 1800,
        'candidate_count': stage['candidate_count'], 'selected_count': stage['selected_count'],
        'symbolic_analyses': analyses, 'sandbox': result['sandbox'],
        'stage_status': {key: value['status'] for key, value in result['stages'].items()},
        'limitation': 'One image and the declared header/empty-body symbolic scenario; not whole-image symbolic coverage or a general throughput guarantee.',
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    record = measure(json.loads(args.report.read_text()))
    record['report_sha256'] = hashlib.sha256(args.report.read_bytes()).hexdigest()
    record['measurement_host'] = {'system': platform.system(), 'release': platform.release(),
        'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
        'memory_bytes': os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')}
    record['measurement_host']['cpu_model'] = next((line.split(':', 1)[1].strip()
        for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown')
    with args.output.open('x') as handle:
        json.dump(record, handle, indent=2)
        handle.write('\n')
    print(json.dumps({key: record[key] for key in ('result', 'scope', 'static_plus_selected_analysis_seconds', 'pipeline_seconds')}))

if __name__ == '__main__':
    main()
