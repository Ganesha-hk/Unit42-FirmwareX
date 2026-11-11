import pytest
from firmwarex.analysis.budgets import Budgets, LIMITS, validate_overrides


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), 0, -1, True, '1', None])
def test_time_budget_rejects_invalid_numbers(value):
    with pytest.raises(ValueError):
        Budgets(seconds=value)


@pytest.mark.parametrize('key', list(LIMITS))
def test_every_budget_ceiling_is_enforced(key):
    with pytest.raises(ValueError):
        Budgets(**{key: LIMITS[key] + 1})
    Budgets(**{key: LIMITS[key]})


@pytest.mark.parametrize('key', [k for k in LIMITS if k != 'seconds'])
def test_counts_must_be_integers(key):
    with pytest.raises(ValueError):
        Budgets(**{key: 1.5})
    with pytest.raises(ValueError):
        Budgets(**{key: True})


def test_controller_and_direct_engine_use_same_contract():
    validate_overrides({})
    assert Budgets(seconds=0.01, merge=False).seconds == 0.01
    for value in [None, [], {'unknown': 1}, {'merge': 1}]:
        with pytest.raises(ValueError):
            validate_overrides(value)
