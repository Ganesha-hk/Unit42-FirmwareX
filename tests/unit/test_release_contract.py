"""Release additions: evidence stays scoped and input paths stay guest-local."""
import pytest
from firmwarex.output_policy import sanitize_output
from firmwarex.vendor_analysis import guest_resolve

@pytest.mark.parametrize('reason',['sampled_profiles','http_harness_verified','applet_verified','program_entry_limited_models'])
def test_profile_outcomes_survive_output_boundary(reason):
    value={'status':'incomplete','reason':reason}
    assert sanitize_output(value,b'synthetic-release-test-salt-32-bytes')==value

def test_guest_resolution_rejects_escape_and_link_cycles(tmp_path):
    (tmp_path/'escape').symlink_to('../../host')
    (tmp_path/'cycle').symlink_to('/cycle')
    for name in ['escape','cycle','../../host']:
        with pytest.raises(ValueError):guest_resolve(tmp_path,name)
