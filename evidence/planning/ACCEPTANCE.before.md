# FirmwareX Acceptance Contract

FirmwareX is accepted only when the PRD Definition of Done is demonstrated.

## Required acceptance conditions

- [ ] End-to-end pipeline works from firmware upload to CWE-classified report.
- [ ] Results are viewable through the dashboard.
- [ ] Extraction succeeds on >90% of the defined standard open-source test set.
- [ ] Binary execution/emulation occurs only inside the sandbox.
- [ ] Workers have proven zero external network egress.
- [ ] CPU quotas are enforced.
- [ ] Memory quotas are enforced.
- [ ] Wall-clock limits are enforced.
- [ ] A quota-breaching job is demonstrably terminated.
- [ ] Findings conform to the normalized finding schema.
- [ ] Findings contain CWE classification.
- [ ] Findings contain confidence.
- [ ] Raw discovered secrets are not persisted by default.
- [ ] Secret fingerprint/redaction behavior is demonstrated.
- [ ] Static audit + basic symbolic trace meets the PRD performance target on
      the representative test image.
- [ ] Required REST API functionality exists.
- [ ] Required dashboard views exist.
- [ ] OpenTelemetry traces job lifecycle stages.
- [ ] Core modules have automated tests.
- [ ] Coverage report exists.
- [ ] README/setup/runbook reproduce a complete run.
- [ ] Architecture documentation matches delivered implementation.
- [ ] Required evidence package exists.

## Evidence required

Evidence must come from actual execution, not manually fabricated examples.

Required evidence includes:

- repository/commit history;
- architecture diagram;
- named permitted firmware extraction output;
- filesystem inventory;
- mitigation matrix;
- checksec comparison;
- QEMU execution evidence;
- no-egress proof;
- quota termination proof;
- symbolic/taint finding;
- diagnostic crash state;
- normalized CWE JSON;
- redacted secret finding;
- proof plaintext secret was not persisted;
- API examples;
- end-to-end run;
- throughput measurement;
- test coverage report.

## Final validation

Generate docs/final-validation.md.

For every PRD requirement record:

Requirement
Implementation
Test
Evidence
PASS/FAIL
Notes

Unknown or untested means FAIL/UNVERIFIED, never PASS.
