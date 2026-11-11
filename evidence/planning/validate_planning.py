"""Validate planning documents only; no application tests or firmware execution."""
from pathlib import Path
import collections, hashlib, json, re
root = Path(__file__).resolve().parents[2]
rows = json.loads((root / "evidence/planning/requirements-index.json").read_text())
ids = [r["id"] for r in rows]
out = {"requirement_count": len(rows), "priority_counts": dict(collections.Counter(r["priority"] for r in rows)),
       "explicit_must_count": sum(r["basis"] == "Explicit MoSCoW Must" for r in rows)}
checks = {"unique_ids": len(ids) == len(set(ids))}
for name in ["REQUIREMENTS.md", "docs/requirements-traceability.md", "TASKS.md", "ACCEPTANCE.md", "docs/implementation-plan.md"]:
    found = set(re.findall(r"FWX-[A-Z]+-\d{3}", (root / name).read_text()))
    out[name] = {"missing_ids": sorted(set(ids) - found), "unknown_ids": sorted(found - set(ids))}
    checks[name + "_coverage"] = found == set(ids)
trace = [l for l in (root / "docs/requirements-traceability.md").read_text().splitlines() if l.startswith("FWX-")]
out["trace_rows"] = len(trace)
checks["trace_complete_not_started"] = len(trace) == len(rows) and all(l.endswith(" | NOT STARTED") for l in trace)
prd = (root / "evidence/planning/prd-full-text.txt").read_text()
refs = " ".join(r["section"] for r in rows)
for tag in ["FR", "SC"]:
    source = set(re.findall(tag + r"-\d\.\d", prd))
    missing = source - set(re.findall(tag + r"-\d\.\d", refs))
    out[tag + "_source_ids"] = sorted(source)
    out[tag + "_missing_refs"] = sorted(missing)
    checks[tag + "_complete"] = not missing
checks["prd_hash_unchanged"] = hashlib.sha256((root / "PRD.docx").read_bytes()).hexdigest() == "03451782008d39e8003efc4ec1ba8a650ec9206a8d5aa1f99ac314467c31fd14"
before = (root / "evidence/planning/TASKS.before.md").read_text()
for item in ["Read and extract entire PRD", "Complete requirements traceability", "Inspect development environment"]:
    before = before.replace("- [ ] " + item, "- [x] " + item, 1)
checks["task_original_preserved_except_completed_planning_checks"] = (root / "TASKS.md").read_text().startswith(before)
checks["acceptance_original_preserved"] = (root / "ACCEPTANCE.md").read_text().startswith((root / "evidence/planning/ACCEPTANCE.before.md").read_text())
checks["record_fields_complete"] = all(all(r.get(k) for k in ["id", "section", "requirement", "priority", "basis", "implementation", "test", "evidence", "day"]) for r in rows)
plan = (root / "docs/implementation-plan.md").read_text()
allocation = [l for l in plan.splitlines() if re.match(r"\| [1-5] \| FWX-", l)]
allocated = re.findall(r"FWX-[A-Z]+-\d{3}", "\n".join(allocation))
checks["day_allocation_exact_once"] = collections.Counter(allocated) == collections.Counter(ids)
out.update({"checks": checks, "application_tests_run": False, "passed": all(checks.values())})
(root / "evidence/planning/document-validation.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps({"passed": out["passed"], "requirements": len(rows), "checks": len(checks), "application_tests_run": False}))
raise SystemExit(0 if out["passed"] else 1)
