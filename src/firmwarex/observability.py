"""OpenTelemetry SDK with a local, content-free exporter; no worker egress."""
import json
import time
from contextlib import contextmanager
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter,SpanExportResult,SimpleSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace
from opentelemetry.trace import SpanContext,TraceFlags,NonRecordingSpan,Status,StatusCode

class LocalExporter(SpanExporter):
    def __init__(self):self.records=[]
    def export(self,spans):
        for span in spans:
            self.records.append({'name':span.name,'trace_id':format(span.context.trace_id,'032x'),'span_id':format(span.context.span_id,'016x'),'status':span.status.status_code.name,'parent_span_id':format(span.parent.span_id,'016x') if span.parent else None,'start_ns':span.start_time,'end_ns':span.end_time,'attributes':dict(span.attributes)})
        return SpanExportResult.SUCCESS
    def shutdown(self):pass

class Observer:
    def __init__(self,job_id,parent=None):
        self.parent=None
        if parent:
            context=SpanContext(int(parent["trace_id"],16),int(parent["span_id"],16),True,TraceFlags(1))
            if not context.is_valid:raise ValueError("invalid trace parent")
            self.parent=trace.set_span_in_context(NonRecordingSpan(context))
        self.exporter=LocalExporter();resource=Resource.create({'service.name':'firmwarex-analysis'})
        self.provider=TracerProvider(resource=resource);self.provider.add_span_processor(SimpleSpanProcessor(self.exporter));self.tracer=self.provider.get_tracer('firmwarex.pipeline','1.0')
        self.reader=InMemoryMetricReader();self.meters=MeterProvider(resource=resource,metric_readers=[self.reader]);meter=self.meters.get_meter('firmwarex.pipeline')
        self.counter=meter.create_counter('firmwarex.stage.completed');self.duration=meter.create_histogram('firmwarex.stage.duration',unit='s');self.job_id=job_id
    def context(self):
        return None if trace.get_current_span().get_span_context().is_valid else self.parent
    @staticmethod
    def carrier(span):
        context=span.get_span_context()
        return {'trace_id':format(context.trace_id,'032x'),'span_id':format(context.span_id,'016x')}
    def interval(self,name,start_ns,end_ns,outcome='completed'):
        if end_ns<start_ns:raise ValueError('invalid interval')
        span=self.tracer.start_span(name,context=self.context(),start_time=start_ns,attributes={'job.id':self.job_id,'outcome':outcome})
        if outcome=='failed':span.set_status(Status(StatusCode.ERROR))
        span.end(end_time=end_ns)
        self.counter.add(1,{'stage':name,'outcome':outcome});self.duration.record((end_ns-start_ns)/1e9,{'stage':name,'outcome':outcome})
        return self.carrier(span)
    @contextmanager
    def stage(self,name):
        started=time.monotonic()
        with self.tracer.start_as_current_span(name,context=self.context(),attributes={'job.id':self.job_id},record_exception=False,set_status_on_exception=False) as span:
            try:yield span
            except Exception:
                span.set_attribute('outcome','failed');span.set_status(Status(StatusCode.ERROR));raise
            else:span.set_attribute('outcome','failed' if span.status.status_code==StatusCode.ERROR else 'completed')
            finally:
                self.counter.add(1,{'stage':name});self.duration.record(time.monotonic()-started,{'stage':name})
    @staticmethod
    def fail(span):
        span.set_status(Status(StatusCode.ERROR))
    def snapshot(self):
        self.provider.force_flush();data=self.reader.get_metrics_data()
        return {'spans':self.exporter.records,'metrics':json.loads(data.to_json()) if data else {}}

    def close(self):
        self.provider.shutdown();self.meters.shutdown()

def merge_snapshots(*snapshots):
    spans=[];resources=[]
    for snapshot in snapshots:
        if not snapshot:continue
        spans.extend(snapshot.get('spans',[]))
        resources.extend(snapshot.get('metrics',{}).get('resource_metrics',[]))
    return {'spans':spans,'metrics':{'resource_metrics':resources}}
