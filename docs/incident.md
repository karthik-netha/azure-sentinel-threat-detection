# LAB-IR-001 simulated identity and logging incident

**Classification:** personal lab simulation. **Disposition:** escalate suspected account
misuse for human review. No real compromise, tenant, or containment action occurred.
All times below are UTC on January 15, 2026; evidence IDs resolve in `data/events.json`.

| Time | Evidence | Observation |
| --- | --- | --- |
| 10:00:00–10:02:15 | spray-00 through spray-09 | Ten failures against five identities from 198.51.100.24 |
| 10:04:10 | success-01 | user0@example.test signs in successfully from the same IP |
| 10:05:30 | role-01 | Same user initiates a role addition; synthetic modifiedProperties names Global Administrator |
| 10:07:00 | delete-01 | Same caller deletes a diagnostic setting successfully |

AUTH-001, IAM-001 and AZ-001 provide separate findings. The successful sign-in is
supporting investigation evidence, not a fourth detection. Correlation uses shared
identity, IP, and time; distinct CorrelationId values are not a cross-service session ID.
The sequence supports a hypothesis of account takeover followed by privilege change
and logging impairment. It does not prove password reuse, token theft, or attacker intent.

Triage separates the 203.0.113.8 shared-NAT case and the approved PIM case from this
sequence using the fixture scenario labels. Those labels are simulation ground truth;
a real investigation would require change tickets, approvals, device and MFA context.

Scope is limited to the supplied account, operation, and resource evidence. There is
no endpoint telemetry, data-access history, or proof of exfiltration. A high-priority
human review is reasonable because the sequence could affect privileged access and
visibility, but actual severity must incorporate asset criticality and corroboration.

Proposed response, **not performed**: preserve original records, verify change approval,
inspect role assignments and sign-in sessions, obtain authorization for any session
revocation or role rollback, and restore diagnostics through approved change control.
Recovery acceptance would require verified logging continuity and reviewed privilege
assignments. Lessons: monitor connector health independently, preserve external audit
copies, and test legitimate PIM activity before deploying noisy role-change detections.
