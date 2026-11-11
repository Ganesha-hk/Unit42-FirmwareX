# Development workflow

Use a focused branch and coherent local milestone commits. All changes land through reviewed pull requests. Sandbox, quota and redaction changes require extra scrutiny. The user must approve pushing, publishing, opening PRs, merging or any external repository action; do not infer approval from the configured remote.

Never commit .env, raw firmware, extracted trees, volumes, environments or caches. Use controlled source fixtures and sanitized evidence. Record actual commands/results in docs/progress.md. Keep unmet PRD requirements visible.

Before untrusted emulation, obtain the mentor isolation/quota sign-off tied to the reviewed code/configuration. Static parsing also runs inside the offline sandbox. This milestone implements no firmware execution.
