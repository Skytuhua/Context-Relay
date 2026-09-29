import hashlib
import struct
import unittest
from macos_signing import constraint_digest


class ConstraintDigestTest(unittest.TestCase):
    def test_extracts_exact_blob_and_rejects_truncation_and_bad_bounds(self):
        blob = struct.pack(">II", 0xfade8181, 12) + b"test"
        signature = struct.pack(">IIIII", 0xfade0cc0, 20 + len(blob), 1, 11, 20) + blob
        image = bytearray(48)
        struct.pack_into("<IIIIIIII", image, 0, 0xfeedfacf, 0x0100000c, 0, 2, 1, 16, 0, 0)
        struct.pack_into("<IIII", image, 32, 0x1d, 16, 48, len(signature))
        image += signature
        self.assertEqual(constraint_digest(image), hashlib.sha256(blob).hexdigest())
        for size in range(len(image)):
            with self.assertRaises(ValueError):
                constraint_digest(image[:size])
        for offset, value, endian in [(0, 0, "<"), (4, 0, "<"), (12, 6, "<"),
                                      (16, 2, "<"), (36, 8, "<"), (40, 0, "<"),
                                      (48, 0, ">"), (56, 65, ">"), (60, 0, ">"),
                                      (64, 0, ">"), (72, 1000, ">")]:
            invalid = bytearray(image)
            struct.pack_into(endian + "I", invalid, offset, value)
            with self.assertRaises(ValueError):
                constraint_digest(invalid)


if __name__ == "__main__":
    unittest.main()
