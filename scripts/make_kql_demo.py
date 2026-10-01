"""Generate self-contained KQL fixtures; run the output in an authorized KQL console.

The output aliases table names with datatable() expressions; it never ingests logs.
"""
import json
from pathlib import Path
events=json.loads(Path('data/events.json').read_text())
schemas={
 'SigninLogs':{'TimeGenerated':'datetime','Id':'string','ResultType':'string','UserPrincipalName':'string','IPAddress':'string'},
 'AuditLogs':{'TimeGenerated':'datetime','Id':'string','OperationName':'string','Result':'string','InitiatedBy':'dynamic','TargetResources':'dynamic','CorrelationId':'string'},
 'AzureActivity':{'TimeGenerated':'datetime','Caller':'string','CallerIpAddress':'string','ResourceId':'string','CorrelationId':'string','OperationNameValue':'string','ActivityStatusValue':'string'}}
def literal(value,kind):
    if kind=='datetime': return 'datetime('+value+')'
    if kind=='dynamic': return 'dynamic('+json.dumps(value)+')'
    return json.dumps(value)
Path('demo').mkdir(exist_ok=True)
for table,schema in schemas.items():
    name={'SigninLogs':'password_spray.kql','AuditLogs':'privilege_change.kql','AzureActivity':'logging_disabled.kql'}[table]
    lines=[', '.join(literal(e.get(field,''),kind) for field,kind in schema.items()) for e in events if e['Table']==table]
    fixture='let '+table+'=datatable('+', '.join(k+':'+v for k,v in schema.items())+')[\n'+',\n'.join(lines)+'\n];\n'
    query=Path('detections',name).read_text().replace('ago(15m)','datetime(2026-01-15T09:55:00Z)').replace('now()','datetime(2026-01-15T10:10:00Z)')
    Path('demo',name).write_text('// SYNTHETIC FIXTURE. Not yet executed against Kusto.\n'+fixture+query)
print('Generated 3 standalone KQL demos; generation does not validate KQL execution.')
