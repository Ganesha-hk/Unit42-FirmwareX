"""Shared bounded-analysis contract, usable without importing the symbolic engine."""
from dataclasses import asdict, dataclass

LIMITS = {'seconds': 120, 'states': 256, 'paths': 10000, 'depth': 5000,
          'steps': 10000, 'memory_mb': 768, 'source_bytes': 256}


def validate_overrides(values):
    if not isinstance(values, dict) or set(values) - set(LIMITS) - {'merge'}:
        raise ValueError('budget fields')
    for key, value in values.items():
        if key == 'merge':
            if type(value) is not bool:
                raise ValueError('merge')
        elif (type(value) not in {int, float} or not 0 < value <= LIMITS[key]
              or (key != 'seconds' and type(value) is not int)):
            raise ValueError('budget')


@dataclass(frozen=True)
class Budgets:
    seconds: float = 20
    states: int = 32
    paths: int = 256
    depth: int = 200
    steps: int = 500
    memory_mb: int = 512
    source_bytes: int = 32
    merge: bool = True

    def __post_init__(self):
        validate_overrides(asdict(self))
