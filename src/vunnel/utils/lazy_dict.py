from collections.abc import Callable
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class LazyDict(dict[K, V], Generic[K, V]):
    """LazyDict presents a dictionary like object, but keys are computed
    the first time they are read and then cached"""

    def __init__(self, compute: Callable[[K], V], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.compute = compute
        self._memoized: dict[K, V] = {}

    def __getitem__(self, key: K) -> V:
        if key not in self._memoized:
            self._memoized[key] = self.compute(key)
        return self._memoized[key]
