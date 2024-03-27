from __future__ import annotations

import hashlib
from enum import Enum

import xxhash


class Method(Enum):
    SHA256 = "sha256"
    XXH64 = "xxh64"

    def digest(self, path: str, label: bool = True, size: int = 65536) -> str:
        hasher = self.hasher()
        with open(path, "rb") as f:
            while b := f.read(size):
                hasher.update(b)
        if label:
            return self.value + ":" + hasher.hexdigest()
        return hasher.hexdigest()

    def hasher(self):  # type: ignore[no-untyped-def]
        if self == self.SHA256:
            return hashlib.sha256()
        if self == self.XXH64:
            return xxhash.xxh64()
        raise ValueError(f"unknown digest label: {self.value}")

    @staticmethod
    def parse(value: str) -> Method:
        try:
            return Method(value.lower().replace("-", "").strip().split(":")[0])
        except ValueError:
            raise ValueError(f"unknown digest label: {value}") from None
