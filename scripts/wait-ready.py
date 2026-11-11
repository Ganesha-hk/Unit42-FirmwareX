"""Wait for HTTP readiness without executing or printing private env values."""
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

root = Path(__file__).resolve().parents[1]
values = dict(line.split('=', 1) for line in (root / '.env').read_text().splitlines()
              if '=' in line and not line.lstrip().startswith('#'))
port = int(os.environ.get('FWX_HTTP_PORT', values.get('FWX_HTTP_PORT', '8000')))
url = f'http://127.0.0.1:{port}'
for attempt in range(90):
    try:
        with urllib.request.urlopen(url + '/health', timeout=2) as response:
            if response.status == 200:
                print(f'FirmwareX is responding at {url}/')
                print('Register with your employee ID, password and privately supplied company code.')
                break
    except (urllib.error.URLError, TimeoutError, OSError):
        pass
    time.sleep(2)
else:
    raise SystemExit('API readiness timed out. Run: docker compose ps; docker compose logs --tail=80 api migrate')
