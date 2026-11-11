from firmwarex.api import normalize_execution_labels

def test_historical_labels_are_neutral_without_changing_results():
    original={'stages':{'emulation':{'authorization':'mentor_authorized','status':'incomplete'},
                        'symbolic':{'reason':'mentor_signoff_required','status':'blocked'}}}
    public=normalize_execution_labels(original)
    assert public['stages']['emulation']=={'authorization':'sandboxed_execution','status':'incomplete'}
    assert public['stages']['symbolic']=={'reason':'execution_disabled','status':'blocked'}
    assert original['stages']['emulation']['authorization']=='mentor_authorized'
