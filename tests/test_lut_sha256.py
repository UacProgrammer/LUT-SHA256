"""Tests de LUT-SHA256 contra hashlib y vectores oficiales.

Ejecutar con:  python3 -m unittest discover tests
o directamente: python3 tests/test_lut_sha256.py
"""
import hashlib
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lut_sha256 import LUT_SHA256, build_tables  # noqa: E402

VECTORES = [
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    # Ejercicios BIP39 del estudio
    (bytes.fromhex("7f" * 16), "87dcde7fa6df23e15fa7ba9b2a1f31408eac832f4e615ea815ae92024e3d818b"),
    (bytes(64), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
]

FRONTERAS = [b"a" * 55, b"a" * 56, b"a" * 57]
LARGOS = [bytes(i % 256 for i in range(1000)), bytes(128), bytes(256)]


class TestDigestos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.memoria = LUT_SHA256(build_tables("memory"))
        cls.velocidad = LUT_SHA256(build_tables("speed"))

    def test_vectores_oficiales(self):
        for msg, ref in VECTORES:
            for motor in (self.memoria, self.velocidad):
                self.assertEqual(motor.digest(msg).hex(), ref, msg=f"{motor=} {msg!r}")

    def test_fronteras_de_bloque(self):
        for msg in FRONTERAS:
            ref = hashlib.sha256(msg).hexdigest()
            self.assertEqual(self.memoria.digest(msg).hex(), ref)
            self.assertEqual(self.velocidad.digest(msg).hex(), ref)

    def test_mensajes_largos_y_bloques_cero(self):
        for msg in LARGOS:
            ref = hashlib.sha256(msg).hexdigest()
            self.assertEqual(self.memoria.digest(msg).hex(), ref)
            self.assertEqual(self.velocidad.digest(msg).hex(), ref)

    def test_equivalencia_aleatoria(self):
        rng = random.Random(20260827)
        for _ in range(50):
            msg = bytes(rng.randrange(256) for _ in range(rng.randrange(200)))
            ref = hashlib.sha256(msg).hexdigest()
            self.assertEqual(self.memoria.digest(msg).hex(), ref)
            self.assertEqual(self.velocidad.digest(msg).hex(), ref)


class TestPrimitivas(unittest.TestCase):
    """Las primitivas del motor se verifican contra la aritmética de referencia."""

    @classmethod
    def setUpClass(cls):
        cls.motor = LUT_SHA256(build_tables("speed"))

    def _by(self, x):
        return [(x >> (8 * i)) & 0xFF for i in range(4)]

    def _wd(self, b):
        return b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24

    def test_wadd_contra_suma(self):
        rng = random.Random(1)
        for _ in range(2000):
            x, y = rng.getrandbits(32), rng.getrandbits(32)
            self.assertEqual(
                self._wd(self.motor._wadd(self._by(x), self._by(y))), (x + y) & 0xFFFFFFFF
            )

    def test_rotaciones_contra_referencia(self):
        rng = random.Random(2)
        for _ in range(2000):
            x, n = rng.getrandbits(32), rng.randrange(32)
            ref = ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
            self.assertEqual(self._wd(self.motor._wrot(self._by(x), n)), ref)
            self.assertEqual(self._wd(self.motor._wshr(self._by(x), n)), x >> n)

    def test_tablas_tadc_exhaustivas(self):
        t = build_tables("speed").taddc
        for a in range(256):
            for b in range(256):
                for c in (0, 1):
                    s = (a + b + c) & 0xFF
                    co = 1 if a + b + c > 255 else 0
                    v = t[max(a, b)][min(a, b)][c]
                    self.assertEqual(v & 0xFF, s)
                    self.assertEqual((v >> 8) & 1, co)


if __name__ == "__main__":
    unittest.main(verbosity=2)
