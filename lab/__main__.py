import json
from pathlib import Path
from .engine import detect,timestamp

def main():
    events=json.loads(Path('data/events.json').read_text())
    scenarios=json.loads(Path('data/scenarios.json').read_text())
    findings=detect(events,timestamp('2026-01-15T10:10:00Z'))
    counts={'true_positive':0,'false_positive':0,'true_negative':0,'false_negative':0}
    for case in scenarios:
        matched=any(f['rule']==case['rule'] and case['evidence'] in f['evidence'] for f in findings)
        key=('true_' if matched==case['malicious'] else 'false_')+('positive' if matched else 'negative')
        counts[key]+=1
    result={'mode':'Python semantic simulation, not KQL execution','evaluation_time':'2026-01-15T10:10:00Z','events':len(events),'scenarios':len(scenarios),'scenario_confusion_matrix':counts,'findings':findings}
    out=Path('evidence'); out.mkdir(exist_ok=True)
    (out/'simulation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
