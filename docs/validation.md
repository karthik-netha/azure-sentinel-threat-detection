# Detection validation and false positives

The model uses the same thresholds, operation names, successful-result filters, case
normalization, and inclusive 15-minute event window as the queries. It is a reference
implementation, not a parser or execution test of KQL. KQL schema and runtime validation
must occur separately; see the cloud acceptance checklist.

`data/scenarios.json` labels eight cases by rule and a representative event ID. A
scenario is matched when a finding includes that ID. `python -m lab` calculates the
confusion matrix rather than using stored expected counts as the output. The unit
tests independently check threshold and edge behavior, not just the scenario totals.

| False positive | Why it matches | Investigation and tuning |
| --- | --- | --- |
| nat-00 through nat-09 | Five users share an egress IP and have stale credentials | Confirm managed devices and NAT ownership; correlate subsequent success and authentication method; avoid globally excluding the IP |
| pim-01 | Approved eligibility addition is still a successful role change | Verify PIM approval, target role, approver and timing; suppress only a documented actor/operation/time combination |

The change-bot exclusion demonstrates a baseline, but a compromised bot can exploit
that blind spot. Prefer expiring change approvals and separate monitoring for the bot.
Unknown callers require investigation, not automatic containment.

Additional known gaps: fixed bins split bursts; events older than the lookback are
missed; duplicate source events may inflate failure counts; make_set caps the returned
user list at 1000; low-and-slow or distributed attacks can stay below thresholds;
new Entra/PIM operation variants may require additional rules. No general accuracy,
MTTR, or false-positive reduction claim follows from this small constructed dataset.
