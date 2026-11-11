from firmwarex.observability import Observer,merge_snapshots

def test_cross_process_trace_parent_and_failure_are_content_free():
 parent=Observer('test-job');carrier=parent.interval('upload',100,200)
 child=Observer('test-job',carrier)
 try:
  with child.stage('failed_stage'):
   raise ValueError('PRIVATE-SENTINEL')
 except ValueError:pass
 result=child.snapshot();span=result['spans'][0]
 assert span['trace_id']==carrier['trace_id'] and span['parent_span_id']==carrier['span_id']
 assert span['status']=='ERROR' and span['attributes']['outcome']=='failed'
 assert 'PRIVATE-SENTINEL' not in str(result)
 assert len(merge_snapshots(parent.snapshot(),result)['spans'])==2
 child.close();parent.close()

def test_returned_error_can_mark_span_failed():
 observer=Observer('job')
 with observer.stage('sandbox') as span:observer.fail(span)
 assert observer.snapshot()['spans'][0]['attributes']['outcome']=='failed'
 observer.close()
