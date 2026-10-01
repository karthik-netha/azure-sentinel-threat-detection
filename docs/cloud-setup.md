# Optional cloud validation and cleanup

This path is not executed evidence. Obtain approval for any billable resource first.
Use a sandbox subscription, a Log Analytics workspace enabled for Sentinel, and an
authorized operator. Separate Sentinel configuration rights from tenant connector
administration. Microsoft documents Sentinel Contributor or equivalent permissions
for rule creation. Entra connector prerequisites and sign-in licensing depend on the
selected log streams; verify current tenant entitlements in the linked official guide.

1. Start with the inline `demo/*.kql` in an already authorized KQL console. Each query
   defines its own table, so no synthetic records are ingested into system tables.
   Expected result counts: password spray 2, role changes 2, logging deletion 1.
   Export actual result rows and record query text, engine, execution time, and any errors.
2. For a cloud lab, configure the Microsoft Entra ID connector for SigninLogs and
   AuditLogs; route the sandbox subscription Activity Log to the workspace through
   diagnostic settings. Check table availability and recent TimeGenerated values.
   The Terraform sibling project routes activity logs but does not onboard Sentinel
   or enable tenant-wide Entra diagnostics.
3. Verify event operation names and field types with a small recent sample in the
   authorized workspace. Do not export real logs to this repository.
4. In Sentinel Analytics, create disabled scheduled rules from `detections/` first.
   Use metadata in `catalog.json`, run every 5 minutes, look back 15 minutes, and
   trigger when results are greater than zero. All queries return TimeGenerated.
   Use one alert per result for a small lab; group repeated alerts into incidents by
   matching entities over one hour. This grouping does not deduplicate query output.
5. Map IP.Address to IPAddress for AUTH-001; map IP.Address to ActorIP for IAM-001
   and CallerIpAddress for AZ-001. Do not map mixed UPN/service-principal strings
   blindly as an Account entity: normalize them separately after checking source data.
6. Use rule simulation, inspect entity mappings and repeated alert behavior, and
   record evidence before enabling rules. The demonstration requires no real spray,
   real privilege escalation, or deletion of a working logging configuration.

Acceptance record (currently all unverified): inline queries execute; expected rows
match; connectors ingest to the intended tables; rules validate; alert entities map;
grouping works; legitimate changes are documented. Mark each item with an actual
date and sanitized evidence only after observing it.

Cleanup: disable/delete only the three named lab rules; remove only lab-owned connector
or diagnostic configurations after confirming no other consumers depend on them.
Remove Sentinel/workspace resources only if dedicated to this lab. Workspace deletion
can have retention and recovery implications. Do not purge shared telemetry.
