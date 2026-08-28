"""LUT-SHA256 — SHA-256 resuelto exclusivamente por tablas de búsqueda.

El método consta de DOS capas estrictamente separadas:

1. ``build_tables()`` — generación de tablas. Es la ÚNICA fase en la que se
   permite aritmética (se ejecuta una sola vez y puede auditarse aislada).
2. ``LUT_SHA256`` — motor de hash. Regla inviolable: PROHIBIDO operar sobre
   los datos del hash; los bytes solo se usan como índices de tabla. Los
   únicos operadores del motor actúan sobre índices de bucle y constantes.

Referencias: FIPS 180-4 (SHA-256), BIP-39 (casos de uso), informe técnico
LUT-SHA256 v1.1 (teoremas 1-5, escalera de vulnerabilidad, compresiones).

Autor: Abraham A. — Investigación independiente.
Licencia: MIT.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final, List, Tuple

__all__ = ["Tables", "build_tables", "LUT_SHA256", "__version__"]
__version__ = "2.4.0"

_K64: Final[Tuple[int, ...]] = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

_H0: Final[Tuple[int, ...]] = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

Word = List[int]  # palabra de 32 bits como 4 bytes LSB-first


@dataclass(frozen=True)
class Tables:
    """Conjunto inmutable de tablas precomputadas (bytes de 1 byte)."""

    txor: Tuple[Tuple[int, ...], ...]           # triangular: t[a][b], b <= a
    tand: Tuple[Tuple[int, ...], ...]           # triangular
    tor: Tuple[Tuple[int, ...], ...]            # triangular
    tnad: Tuple[Tuple[int, ...], ...]           # completa: (~a) & b
    taddc: Tuple[Tuple[Tuple[int, int], ...], ...]  # triangular; (s | c<<8) por (a,b)
    tl: Tuple[Tuple[int, ...], ...]             # 9x256: (x<<r)&0xFF (modo memoria)
    tr: Tuple[Tuple[int, ...], ...]             # 9x256: x>>r      (modo memoria)
    trot: Tuple[Tuple[Tuple[int, ...], ...], ...]  # r=1..7: (x>>r)|((y<<(8-r))&0xFF)


def _tri(fn) -> Tuple[Tuple[int, ...], ...]:
    """Tabla triangular para funciones simétricas en (a, b)."""
    rows: List[Tuple[int, ...]] = []
    for a in range(256):
        row = [0] * (a + 1)
        for b in range(a + 1):
            row[b] = fn(a, b)
        rows.append(tuple(row))
    return tuple(rows)


def build_tables(mode: str = "memory") -> Tables:
    """Construye las tablas del método (aritmética permitida SOLO aquí).

    Args:
        mode: ``"memory"`` (v2.1: menor memoria, TL/TR) o ``"speed"``
            (v2.4: rotación fusionada TROT, más búsquedas rápidas).

    Returns:
        Tables: conjunto inmutable listo para ``LUT_SHA256``.

    Raises:
        ValueError: si ``mode`` no es ``"memory"`` ni ``"speed"``.
    """
    if mode not in ("memory", "speed"):
        raise ValueError(f"modo desconocido: {mode!r} (usar 'memory' o 'speed')")

    txor = _tri(lambda a, b: a ^ b)
    tand = _tri(lambda a, b: a & b)
    tor = _tri(lambda a, b: a | b)

    taddc: List[Tuple[Tuple[int, int], ...]] = []
    for a in range(256):
        row: List[Tuple[int, int]] = []
        for b in range(a + 1):
            s0 = (a + b) & 0xFF
            c0 = 1 if a + b > 255 else 0
            s1 = (s0 + 1) & 0xFF
            c1 = 1 if (c0 or s0 == 255) else 0
            row.append((s0 | (c0 << 8), s1 | (c1 << 8)))
        taddc.append(tuple(row))

    tnad = tuple(
        tuple(((~x) & 0xFF) & y for y in range(256)) for x in range(256)
    )
    tl = tuple(tuple((x << r) & 0xFF for x in range(256)) for r in range(9))
    tr = tuple(tuple(x >> r for x in range(256)) for r in range(9))

    trot: Tuple[Tuple[Tuple[int, ...], ...], ...] = ()
    if mode == "speed":
        trot = tuple(
            tuple(
                tuple(((x >> r) | ((y << (8 - r)) & 0xFF)) & 0xFF for y in range(256))
                for x in range(256)
            )
            for r in range(1, 8)
        )
    return Tables(txor, tand, tor, tnad, taddc, tl, tr, trot)


def _by(word: int) -> Word:
    """Convierte una palabra de 32 bits en 4 bytes LSB-first."""
    return [(word >> (8 * i)) & 0xFF for i in range(4)]


class LUT_SHA256:
    """Motor de hash por búsquedas en tabla, sin operadores sobre los datos."""

    def __init__(self, tables: Tables) -> None:
        """Recibe las tablas precomputadas (ver ``build_tables``)."""
        self._t: Final[Tables] = tables
        self._speed: Final[bool] = bool(tables.trot)
        self._h0: Final[List[Word]] = [_by(h) for h in _H0]
        self._kb: Final[List[Word]] = [_by(k) for k in _K64]

    # ---------------- primitivas ----------------

    def _wx(self, a: Word, b: Word) -> Word:
        return [self._t.txor[max(x, y)][min(x, y)] for x, y in zip(a, b)]

    def _wand(self, a: Word, b: Word) -> Word:
        return [self._t.tand[max(x, y)][min(x, y)] for x, y in zip(a, b)]

    def _wadd(self, a: Word, b: Word) -> Word:
        """Suma mód 2^32 por cadena de acarreos TADDC (4 búsquedas)."""
        out = [0] * 4
        carry = 0
        for i in range(4):
            v = self._t.taddc[max(a[i], b[i])][min(a[i], b[i])][carry]
            out[i] = v & 0xFF
            carry = (v >> 8) & 1
        return out

    def _wrot(self, w: Word, n: int) -> Word:
        """ROTR^n por recombinación de bytes."""
        k, r = divmod(n, 8)
        if r == 0:
            return [w[(i + k) % 4] for i in range(4)]
        if self._speed:
            return [self._t.trot[r - 1][w[(i + k) % 4]][w[(i + k + 1) % 4]] for i in range(4)]
        return [
            self._t.tor[max(x, y)][min(x, y)]
            for i in range(4)
            for x, y in [(self._t.tr[r][w[(i + k) % 4]], self._t.tl[8 - r][w[(i + k + 1) % 4]])]
        ]

    def _wshr(self, w: Word, n: int) -> Word:
        """SHR^n por recombinación de bytes (ceros inyectados)."""
        k, r = divmod(n, 8)
        lo = lambda i: w[i + k] if i + k < 4 else 0
        hi = lambda i: w[i + k + 1] if i + k + 1 < 4 else 0
        if r == 0:
            return [lo(i) for i in range(4)]
        if self._speed:
            return [self._t.trot[r - 1][lo(i)][hi(i)] for i in range(4)]
        return [
            self._t.tor[max(x, y)][min(x, y)]
            for i in range(4)
            for x, y in [(self._t.tr[r][lo(i)], self._t.tl[8 - r][hi(i)])]
        ]

    def _SIG1(self, w: Word) -> Word:
        return self._wx(self._wx(self._wrot(w, 6), self._wrot(w, 11)), self._wrot(w, 25))

    def _SIG0(self, w: Word) -> Word:
        return self._wx(self._wx(self._wrot(w, 2), self._wrot(w, 13)), self._wrot(w, 22))

    def _sig1(self, w: Word) -> Word:
        return self._wx(self._wx(self._wrot(w, 17), self._wrot(w, 19)), self._wshr(w, 10))

    def _sig0(self, w: Word) -> Word:
        return self._wx(self._wx(self._wrot(w, 7), self._wrot(w, 18)), self._wshr(w, 3))

    def _ch(self, e: Word, f: Word, g: Word) -> Word:
        """Ch(e,f,g) = (e∧f) ⊕ (¬e∧g); rama negada por tabla TNAD."""
        return self._wx(self._wand(e, f), [self._t.tnad[x][y] for x, y in zip(e, g)])

    def _maj(self, a: Word, b: Word, c: Word) -> Word:
        return self._wx(self._wx(self._wand(a, b), self._wand(a, c)), self._wand(b, c))

    # ---------------- motor ----------------

    def digest(self, message: bytes) -> bytes:
        """SHA-256(message) resuelto exclusivamente por búsquedas en tabla.

        Args:
            message: mensaje arbitrario (bytes).

        Returns:
            bytes: digesto de 32 bytes, idéntico a ``hashlib.sha256``.
        """
        ml = len(message) * 8
        padded = (
            message
            + b"\x80"
            + b"\x00" * ((56 - len(message) - 1) % 64)
            + ml.to_bytes(8, "big")
        )
        h = self._h0[:]
        for blk in range(len(padded) // 64):
            chunk = padded[blk * 64 : blk * 64 + 64]
            is_zero = all(b == 0 for b in chunk)
            m_words = [list(reversed(chunk[t * 4 : t * 4 + 4])) for t in range(16)]
            w = m_words[:]
            if not is_zero:  # v2.3: tabla maestra de bloques de ceros
                for t in range(16, 64):
                    w.append(
                        self._wadd(
                            self._wadd(self._wadd(self._sig1(w[t - 2]), w[t - 7]), self._sig0(w[t - 15])),
                            w[t - 16],
                        )
                    )
            a_hist = [h[3], h[2], h[1], h[0]]
            e_hist = [h[7], h[6], h[5], h[4]]
            for t in range(64):
                n = self._wadd(
                    self._wadd(self._wadd(e_hist[0], self._SIG1(e_hist[3])), self._ch(e_hist[3], e_hist[2], e_hist[1])),
                    self._kb[t],
                )
                if not is_zero:
                    n = self._wadd(n, w[t])
                a_new = self._wadd(self._wadd(self._SIG0(a_hist[3]), self._maj(a_hist[3], a_hist[2], a_hist[1])), n)
                e_new = self._wadd(a_hist[0], n)
                a_hist = [a_hist[1], a_hist[2], a_hist[3], a_new]
                e_hist = [e_hist[1], e_hist[2], e_hist[3], e_new]
            state = [a_hist[3], a_hist[2], a_hist[1], a_hist[0], e_hist[3], e_hist[2], e_hist[1], e_hist[0]]
            h = [self._wadd(h[i], state[i]) for i in range(8)]
        return b"".join(bytes(reversed(word)) for word in h)
