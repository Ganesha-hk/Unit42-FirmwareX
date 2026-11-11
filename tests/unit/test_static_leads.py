from pathlib import Path
from firmwarex.static import audit_elf

def test_banned_function_and_writable_executable_leads():
 result=audit_elf(Path('/fixtures/static-risk'),Path('/fixtures'))
 assert result['banned_functions']==['strcpy']
 assert result['wx_segments']

def test_hardened_fixture_has_no_writable_executable_segments():
 result=audit_elf(Path('/fixtures/rootfs/bin/strong'),Path('/fixtures/rootfs'))
 assert result['wx_segments']==[]
