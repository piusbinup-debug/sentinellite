"""SentinelLite: offline educational static file-risk classifier.

No file execution, network access, deletion or quarantine. Not antivirus.
The model learns from illustrative synthetic vectors, not real malware.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import stat

MAX_BYTES = 5 * 1024 * 1024
FEATURES = (
    "executable_name", "double_extension", "mz_header", "high_entropy",
    "shell_marker", "download_marker", "persistence_marker", "encoding_marker",
)
EXECUTABLE = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
DOCUMENT = {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}
MARKERS = (
    (b"powershell", b"cmd.exe", b"wscript.shell"),
    (b"downloadstring", b"downloadfile", b"invoke-webrequest"),
    (b"currentversion\\run", b"schtasks", b"startup"),
    (b"frombase64string", b"-encodedcommand", b"base64.b64decode"),
)
TRAINING = (
    "00000000:0", "10000000:0", "10100000:0", "00010000:0",
    "10001000:0", "00000100:0", "00000010:0", "00000001:0",
    "10110000:0", "10000100:0", "00001000:0", "10000010:0",
    "11001111:1", "11111111:1", "10001111:1", "00001111:1",
    "11110000:1", "11001001:1", "10110110:1", "10001011:1",
    "11000110:1", "00111101:1", "10010111:1", "01001101:1",
)


def entropy(data):
    """Shannon entropy in bits per byte; empty content has entropy zero."""
    if not data:
        return 0.0
    return -sum((n / len(data)) * math.log2(n / len(data))
                for n in Counter(data).values())


def extract(name, data):
    suffixes = Path(name.lower()).suffixes
    ext = suffixes[-1] if suffixes else ""
    hidden = (len(suffixes) > 1 and suffixes[-2] in DOCUMENT
              and ext in EXECUTABLE)
    h = entropy(data)
    lower = data.lower()
    bits = [int(ext in EXECUTABLE), int(hidden),
            int(data.startswith(b"MZ")), int(len(data) >= 1024 and h >= 7.2)]
    bits.extend(int(any(m in lower for m in group)) for group in MARKERS)
    return bits, h


def fit(rows=TRAINING):
    """Train Bernoulli Naive Bayes with Laplace smoothing, alpha=1."""
    groups = {0: [], 1: []}
    for row in rows:
        vector, label = row.split(":")
        groups[int(label)].append([int(bit) for bit in vector])
    model = {}
    for label, vectors in groups.items():
        n = len(vectors)
        if not n:
            raise ValueError("Training requires both classes")
        probabilities = [(sum(v[i] for v in vectors) + 1) / (n + 2)
                         for i in range(len(FEATURES))]
        model[label] = (n / len(rows), probabilities)
    return model


def predict(bits, model):
    logs = []
    for label in (0, 1):
        prior, probabilities = model[label]
        value = math.log(prior)
        for bit, p in zip(bits, probabilities):
            value += math.log(p if bit else 1 - p)
        logs.append(value)
    weights = [math.exp(value - max(logs)) for value in logs]
    return weights[1] / sum(weights)


def risk_label(score):
    if score >= 0.80:
        return "HIGH - review required"
    if score >= 0.50:
        return "MEDIUM - inspect manually"
    return "LOW - not a safety guarantee"


def scan(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Only regular files; symlinks are not accepted")
    if info.st_size > MAX_BYTES:
        raise ValueError("File exceeds the 5 MiB limit")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("File exceeds the 5 MiB limit")
    if not data:
        raise ValueError("Empty file: no meaningful content to assess")
    bits, h = extract(path.name, data)
    score = predict(bits, fit())
    return {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(h, 4),
        "features": dict(zip(FEATURES, bits)),
        "indicators": [key for key, bit in zip(FEATURES, bits) if bit],
        "model_score": round(score, 6),
        "risk": risk_label(score),
        "warning": "Synthetic-trained score; not malware probability. "
                   "No indicators does not mean safe.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="One authorized local file")
    parser.add_argument("--json", action="store_true",
                        help="Print machine-readable result to stdout")
    args = parser.parse_args()
    try:
        result = scan(args.file)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Scan error: {exc}\n")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("SENTINELLITE | STATIC FILE RISK REPORT")
        for key in ("file", "bytes", "sha256", "entropy", "risk"):
            print(f"{key}: {result[key]}")
        print(f"Model score: {result['model_score']:.6f}")
        print("Indicators: " + (", ".join(result["indicators"]) or "none"))
        print(result["warning"])


if __name__ == "__main__":
    main()
