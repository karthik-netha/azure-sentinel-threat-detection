# Ten-minute demo and interview guide

1. Explain the problem and show the README architecture (one minute).
2. Run `python -m unittest discover -s tests -v`; explain why these tests are not KQL
   execution (two minutes).
3. Run `python -m lab`, open `evidence/simulation.json`, and trace spray-00 to its
   finding. Show the two deliberate false positives (two minutes).
4. Open `detections/password_spray.kql`; explain distinct users, UTC bins, threshold,
   and the split-bin unit test. Open the inline demo to explain the next cloud step.
5. Walk through LAB-IR-001 and distinguish observation, hypothesis, and proposed action.

**Why not treat every failed sign-in as a password attack?** This rule filters selected
error codes and aggregates multiple accounts. Shared egress and stale credentials can
still produce the same signal; the simulation demonstrates that ambiguity.

**Why retain raw TargetResources?** Entra audit payloads vary. Preserving nested details
lets the analyst verify target identity and role rather than relying on an array position.

**How do you handle duplicate alerts?** Overlapping schedules can repeat a finding.
The guide proposes incident grouping, but grouping is not event deduplication. A next
iteration would test stable event IDs and ingestion-time scheduling against real data.

**What does ATT&CK mapping prove?** Only that a detection is relevant to a documented
behavior hypothesis. It does not establish compromise or complete technique coverage.

**What did you actually test?** Eleven local reference-model tests and synthetic output.
KQL compilation, connector ingestion, rule scheduling, and entity mapping await cloud validation.
