# LUT-SHA256

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Paper: CC BY-NC-ND 4.0](https://img.shields.io/badge/Paper-CC%20BY--NC--ND%204.0-lightgrey.svg)](docs/LICENSE-PAPER.txt)
[![Language](https://img.shields.io/badge/Python-3.10%2B-green.svg)](#)
[![Version](https://img.shields.io/badge/version-2.4.0-orange.svg)](#)

> **LUT-SHA256: Arithmetic-Free Execution of SHA-256 through Chained Look-Up Tables**  
> *Abraham A. — Independent Research*

**Abstract.** LUT-SHA256 executes the SHA-256 compression function without ever applying an arithmetic, logical, or shift operation to message data: bytes act only as indices into precomputed tables. Addition modulo 2³² becomes a chained byte-carry table (TADDC); rotations become byte recombination (TROT). The method is *provably* equivalent to FIPS 180-4 and digest-identical in every tested scenario (FIPS vectors, BIP39 exercises, block boundaries, long messages, zero blocks).

## Architecture and Key Theorems

| Theorem / Feature | Concept | PDF Section |
|---|---|---|
| T1 | Functional decomposition | §2.1 |
| T2 | Byte-locality of primitives | §2.1 |
| T3 | TADDC carry chain (induction) | §2.1 |
| T4 | Rotations via byte recombination | §2.1 |
| T5 | Equivalence with SHA-256 | §2.1 |
| Vulnerability Ladder V1.0–V1.7 | Side-channel analysis | §7 |
| Compression v2.0–v2.4 | Fused tables, triangular storage, TROT, zero-blocks | §8 |

**Documents:**
- Academic Paper (IEEE format): [paper_LUT-SHA256.pdf](https://zenodo.org/records/22140328)
- Complete Technical Report (v1.1, Spanish): [`informe_LUT-SHA256.pdf`]([../LUT-SHA256_EN.pdf](https://github.com/UacProgrammer/LUT-SHA256/blob/main/LUT-SHA256_EN.pdf))

## Installation and Usage


```bash
git clone https://github.com/UacProgrammer/LUT-SHA256
cd LUT-SHA256
python3 -m venv .venv && source .venv/bin/activate
No external dependencies; requires Python 3.10+
```

```python
from lut_sha256 import build_tables, LUT_SHA256

tables = build_tables(mode="speed")   # "memory" | "speed"
hash_fn = LUT_SHA256(tables)
assert hash_fn.digest(b"abc").hex() == \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

Tests:

```bash
python3 -m unittest discover tests
# Includes: FIPS vectors, BIP39 exercises, 55/56/57 byte boundaries, 
# long messages, zero blocks, 50 random messages, and primitive validation against arithmetic.
```

## Limitations and Use Cases

**Advantages (FPGAs, Secure Elements, Compute-in-Memory)**: The circuit shifts from ~116k Boolean gates to ~8–17k memory reads per block. It is ideal for SRAM-rich, logic-poor substrates with certified tables in ROM. The v2.3 mode (master zero-blocks) saves ~2,000 lookups per padding block, which is highly relevant for PBKDF2/BIP39 workloads.

**Disadvantages (GPUs)**: Data-dependent, non-coalesced memory accesses cause per-block throughput to collapse compared to vectorized arithmetic implementations. This is not a mining accelerator.

**Security**: Equivalence (Theorem 5) preserves 2²⁵⁶ preimage and 2¹²⁸ collision resistance. However, the memory access pattern is an inherent side-channel (see the V1.0–V1.7 ladder in the report). Do not use in production without constant-time access mitigations.

## Support

If you found this project interesting or useful for your research, you can support independent cryptography research here: Bitcoin (SegWit): `bc1qqgqyu462z3n6lduvahfuvpm0lp6rzpkxal92t9`

## License

- Code: **MIT** ([`LICENSE`](LICENSE))
- Technical Report: **CC BY-NC-ND 4.0** ([`../paper/LICENSE-PAPER.txt`](../paper/LICENSE-PAPER.txt))

---

## Structure of `lut_sha256.py`

```python
"""LUT-SHA256: SHA-256 via chained look-up tables.

Module divided into TWO independent layers:
  1) Table generation (one-time setup, Python arithmetic allowed).
  2) Hash engine (lookups ONLY; operating on data is PROHIBITED).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Final, List, Tuple

@dataclass(frozen=True)
class Tables:
    """Immutable set of precomputed tables."""
    txor: Tuple[Tuple[int, ...], ...]     # triangular: t[a][b], b <= a
    tand: Tuple[Tuple[int, ...], ...]
    taddc: Tuple[Tuple[Tuple[int, int], ...], ...]  # (s | c<<8) per (a,b)
    tnad: Tuple[Tuple[int, ...], ...]     # (~a) & b  (non-symmetric)
    trot: Tuple[Tuple[Tuple[int, ...], ...], ...]   # r=1..7

def build_tables(mode: str = "memory") -> Tables:
    """Builds the tables (arithmetic allowed ONLY here).

    Args:
        mode: 'memory' (v2.1) or 'speed' (v2.4 with TROT).

    Returns:
        Tables: Immutable object ready for LUT_SHA256.
    """
    ...

class LUT_SHA256:
    """Hash engine with no operators applied to data."""

    def __init__(self, tables: Tables) -> None: ...
    
    def digest(self, message: bytes) -> bytes:
        """SHA-256(message) resolved exclusively via table lookups."""
```

**Style Rules:** PEP 8; type hints on all signatures; Google-style docstrings; the only arithmetic operators in the engine act on loop indices and counters, never on the data; strict separation of build_tables (arithmetic) from the engine (lookups) to allow independent auditing of each layer; unit tests per primitive + official vector test suite.
