"""Check the local repository has the documented delivery baseline."""
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
required = ['README.md', 'CONTRIBUTING.md', 'docs/runbook.md', 'compose.yaml', 'AGENTS.md']
for name in required:
    assert (root / name).is_file(), name
history = subprocess.check_output(['git', 'log', '--format=%H %s', '-12'], cwd=root, text=True).splitlines()
assert len(history) >= 4
assert 'pull request' in (root / 'CONTRIBUTING.md').read_text().lower()
assert 'docker compose' in (root / 'docs/runbook.md').read_text().lower()
print(json.dumps({'status': 'passed', 'required_files': required, 'recent_commits': history,
                  'scope': 'Local version-control history and documented review workflow. It does not substitute for the separate required PR review.'}, indent=2))
