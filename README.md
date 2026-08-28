# LUT-SHA256

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Paper: CC BY-NC-ND 4.0](https://img.shields.io/badge/Paper-CC%20BY--NC--ND%204.0-lightgrey.svg)](docs/LICENSE-PAPER.txt)
[![Language](https://img.shields.io/badge/Python-3.10%2B-green.svg)](#)
[![Version](https://img.shields.io/badge/version-2.4.0-orange.svg)](#)

> **LUT-SHA256: Arithmetic-Free Execution of SHA-256 through Chained Look-Up Tables**
> *Abraham A. — Independent Research*

**Abstract.** LUT-SHA256 executes the SHA-256 compression function without ever applying an arithmetic, logical, or shift operation to message data: bytes act only as indices into precomputed tables. Addition modulo 2³² becomes a chained byte-carry table (TADDC); rotations become byte recombination (TROT). The method is *provably* equivalent to FIPS 180-4 and digest-identical in every tested scenario (FIPS vectors, BIP39 exercises, block boundaries, long messages, zero blocks).

## Arquitectura y Teoremas Clave

| Teorema | Idea | PDF |
|---|---|---|
| T1 | Descomposición funcional | §2.1 |
| T2 | Byte-localidad de las primitivas | §2.1 |
| T3 | Cadena de acarreos TADDC (inducción) | §2.1 |
| T4 | Rotaciones por recombinación de bytes | §2.1 |
| T5 | Equivalencia con SHA-256 | §2.1 |
| Escalera V1.0–V1.7 | Análisis de canal lateral | §7 |
| Compresión v2.0–v2.4 | Tablas fusionadas, triangular, TROT, cero-bloques | §8 |

Documentos:
- Paper académico (IEEE): ([../paper/paper_LUT-SHA256.pdf](https://zenodo.org/records/22140328))
- Informe técnico completo (v1.1): [`../paper/informe_LUT-SHA256.pdf`](../paper/informe_LUT-SHA256.pdf)

## Instalación y Uso

```bash
git clone https://github.com/UacProgrammer/LUT-SHA256
cd LUT-SHA256
python3 -m venv .venv && source .venv/bin/activate
# sin dependencias externas; solo Python 3.10+
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
# vectores FIPS, ejercicios BIP39, fronteras 55/56/57, mensajes largos,
# bloques de ceros, 50 mensajes aleatorios y primitivas contra la aritmética
```

## Limitaciones y Casos de Uso

**A favor (FPGAs, Secure Elements, CIM):** el circuito pasa de ~116k puertas booleanas a ~8–17k lecturas de memoria por bloque; ideal para sustratos ricos en SRAM y pobres en lógica, con tablas certificadas en ROM. El modo v2.3 (bloques de ceros maestros) ahorra ~2.000 búsquedas por bloque de relleno — relevante para PBKDF2/BIP39.

**En contra (GPUs):** accesos no coalescentes dependientes del dato; el rendimiento por bloque colapsa frente a implementaciones vectorizadas. **No** es un acelerador de minería.

**Seguridad:** la equivalencia (Teorema 5) preserva preimagen 2²⁵⁶ y colisión 2¹²⁸, pero el patrón de accesos es un canal lateral inherente (ver la escalera V1.0–V1.7 en el informe). No usar en producción sin acceso de tiempo constante.

## Apoyo

Si este proyecto te ha parecido interesante o te ha sido útil para tu investigación, puedes apoyar el trabajo independiente de criptografía aquí: Bitcoin (SegWit): `bc1qqgqyu462z3n6lduvahfuvpm0lp6rzpkxal92t9`

## Licencia

- Código: **MIT** ([`LICENSE`](LICENSE))
- Paper e informe: **CC BY-NC-ND 4.0** ([`../paper/LICENSE-PAPER.txt`](../paper/LICENSE-PAPER.txt))

---

## Estructura de `lut_sha256.py`

```python
"""LUT-SHA256: SHA-256 por tablas de búsqueda encadenadas.

Módulo dividido en DOS capas independientes:
  1) Generación de tablas (una sola vez, con aritmética Python).
  2) Motor de hash (solo búsquedas; PROHIBIDO operar sobre los datos).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Final, List, Tuple

@dataclass(frozen=True)
class Tables:
    """Conjunto inmutable de tablas precomputadas."""
    txor: Tuple[Tuple[int, ...], ...]     # triangular: t[a][b], b <= a
    tand: Tuple[Tuple[int, ...], ...]
    taddc: Tuple[Tuple[Tuple[int, int], ...], ...]  # (s | c<<8) por (a,b)
    tnad: Tuple[Tuple[int, ...], ...]     # (~a) & b  (no simétrico)
    trot: Tuple[Tuple[Tuple[int, ...], ...], ...]   # r=1..7

def build_tables(mode: str = "memory") -> Tables:
    """Construye las tablas (aritmética permitida SOLO aquí).

    Args:
        mode: 'memory' (v2.1) o 'speed' (v2.4 con TROT).

    Returns:
        Tables: objeto inmutable listo para LUT_SHA256.
    """
    ...

class LUT_SHA256:
    """Motor de hash sin operadores sobre datos."""

    def __init__(self, tables: Tables) -> None: ...
    def digest(self, message: bytes) -> bytes:
        """SHA-256(message) resuelto exclusivamente por búsquedas."""
        ...
```

**Reglas de estilo:** PEP 8; type hints en todas las firmas; docstrings estilo Google; los únicos operadores aritméticos del motor actúan sobre *índices de bucle y contadores*, nunca sobre los datos; separar `build_tables` (aritmética) del motor (búsquedas) para auditar cada capa por separado; tests unitarios por primitiva + suite de vectores oficiales.
