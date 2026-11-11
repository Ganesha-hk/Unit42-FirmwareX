"""Check benchmark interval accounting and incomplete-result rejection."""
import copy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('benchmark', Path(__file__).with_name('benchmark-real-report.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
report = {'firmware_id':'test','sha256':'test','jobs':[{'status':'complete','job_id':'test','result':{
    'observability':{'spans':[
        {'name':'static','start_ns':1_000_000_000,'end_ns':3_000_000_000},
        {'name':'vendor_analysis','start_ns':3_000_000_000,'end_ns':7_000_000_000},
        {'name':'pipeline','start_ns':0,'end_ns':8_000_000_000}]},
    'sandbox':{},'stages':{'static':{'status':'completed'},'symbolic':{'status':'completed',
        'candidate_count':171,'selected_count':3,'analyses':[{'status':'completed','reasons':[]}]}}}}]}
assert module.measure(report)['static_plus_selected_analysis_seconds'] == 6
assert module.measure(report)['pipeline_seconds'] == 8
assert module.measure(report)['result'] == 'PASS'
incomplete = copy.deepcopy(report)
incomplete['jobs'][0]['result']['stages']['symbolic']['analyses'][0]['reasons'] = ['depth_budget']
assert module.measure(incomplete)['result'] == 'FAIL'
slow = copy.deepcopy(report)
slow['jobs'][0]['result']['observability']['spans'][1]['end_ns'] = 1801_000_000_000
assert module.measure(slow)['result'] == 'FAIL'
print('PASS: non-overlapping interval, incomplete rejection, strict 1800-second threshold')
