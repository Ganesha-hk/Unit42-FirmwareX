import pytest
from firmwarex.fuzz.corpus import seeds,minimize
@pytest.mark.parametrize('protocol',['http','upnp','mqtt'])
def test_seeded_protocol_corpus(protocol):
 assert seeds(protocol,42)==seeds(protocol,42)
 assert len(seeds(protocol))==4 and all(0<len(x)<=512 for x in seeds(protocol))
def test_bounded_minimizer_preserves_diagnostic_condition():
 result,attempts=minimize(b'paddingXYZmore',lambda value:b'XYZ' in value,24)
 assert b'XYZ' in result and len(result)<len(b'paddingXYZmore') and attempts<=24
