"""Harmless tests; temporary fixtures are bytes, never executed."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from scanner import MAX_BYTES, entropy, extract, fit, predict, risk_label, scan


class ScannerTests(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(entropy(b""), 0)
        self.assertEqual(entropy(b"a" * 2000), 0)
        self.assertAlmostEqual(entropy(bytes(range(256)) * 8), 8)

    def test_extension(self):
        bits, _ = extract("BILL.PDF.EXE", b"MZ example")
        self.assertEqual(bits[:3], [1, 1, 1])

    def test_markers(self):
        data = b"PowerShell DownloadString CurrentVersion\\Run FromBase64String"
        self.assertEqual(extract("note.txt", data)[0][4:], [1, 1, 1, 1])

    def test_entropy_feature(self):
        self.assertEqual(extract("x.bin", bytes(range(256)) * 8)[0][3], 1)
        self.assertEqual(extract("x.bin", bytes(range(256)))[0][3], 0)

    def test_smoothing(self):
        model = fit()
        self.assertEqual(model[0][0], 0.5)
        for _, probabilities in model.values():
            self.assertTrue(all(0 < p < 1 for p in probabilities))

    def test_model_order(self):
        model = fit()
        low = predict([0] * 8, model)
        high = predict([1] * 8, model)
        self.assertTrue(0 < low < 0.5 < 0.8 < high < 1)

    def test_thresholds(self):
        for score, expected in [(0.49, "LOW"), (0.5, "MEDIUM"),
                                (0.799, "MEDIUM"), (0.8, "HIGH")]:
            self.assertTrue(risk_label(score).startswith(expected))

    def test_scan_hash_and_preservation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "notes.txt"
            data = b"Classroom notes on computer networks.\n"
            path.write_bytes(data)
            result = scan(path)
            self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(result["risk"].startswith("LOW"))
            self.assertEqual(path.read_bytes(), data)

    def test_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(ValueError):
                scan(root)
            with self.assertRaises(OSError):
                scan(root / "missing")
            path = root / "empty"
            path.touch()
            with self.assertRaises(ValueError):
                scan(path)
            with path.open("wb") as stream:
                stream.truncate(MAX_BYTES + 1)
            with self.assertRaises(ValueError):
                scan(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
