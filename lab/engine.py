"""Small Python reference model of the documented detection semantics.

It is deliberately not a KQL interpreter. Azure execution is separately unverified.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

def timestamp(value):
    at = datetime.fromisoformat(value.replace('Z','+00:00'))
    if at.tzinfo is None:
        raise ValueError('Timestamps must include timezone')
    try:
        return at.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError('Timestamp out of representable range')

def detect(events, now, approved=('change-bot@example.test',)):
    groups = defaultdict(list)
    findings=[]
    for e in events:
        at=timestamp(e['TimeGenerated'])
        if not now-timedelta(minutes=15) <= at <= now:
            continue
        if e['Table']=='SigninLogs' and e.get('ResultType') in ('50126','50053') and e.get('IPAddress') and e.get('UserPrincipalName'):
            bucket=at.replace(minute=at.minute//5*5,second=0,microsecond=0)
            groups[(e['IPAddress'],bucket.isoformat())].append(e)
        if e['Table']=='AuditLogs' and e.get('OperationName','').lower() in ('add member to role','add eligible member to role') and e.get('Result','').lower()=='success':
            initiator=e.get('InitiatedBy',{})
            actor=initiator.get('user',{}).get('userPrincipalName') or initiator.get('app',{}).get('servicePrincipalId','')
            findings.append({'rule':'IAM-001','actor':actor,'evidence':[e['Id']]})
        if e['Table']=='AzureActivity' and e.get('OperationNameValue','').upper()=='MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE' and e.get('ActivityStatusValue','').lower()=='success' and e.get('Caller','').lower() not in approved:
            findings.append({'rule':'AZ-001','actor':e.get('Caller',''),'evidence':[e['Id']]})
    for (ip,bucket),rows in sorted(groups.items()):
        users={r['UserPrincipalName'].lower() for r in rows}
        if len(rows)>=10 and len(users)>=5:
            findings.append({'rule':'AUTH-001','ip':ip,'window':bucket,'failures':len(rows),'distinct_users':len(users),'evidence':sorted(r['Id'] for r in rows)})
    return sorted(findings,key=lambda f:(f['rule'],str(f)))
