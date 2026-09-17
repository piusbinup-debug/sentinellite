# SentinelLite

Recreated from the source listings in CIA3_SentinelLite_Project 2362527.pdf.
Requires Python 3.10 or newer; no third-party packages.

Run from this folder:

```text
python scanner.py samples/notes.txt
python scanner.py samples/indicator_demo.txt
python scanner.py samples/indicator_demo.txt --json
python -m unittest -v
```

## One-click classroom demonstration

On Windows, double-click `RUN_DEMO.bat`. It runs the tests and both harmless
sample scans, pausing between stages so the presenter can explain each result.

On Windows, use `py` if Python is installed through the Python launcher.

The scanner reads files without executing or modifying them. Its synthetic-trained
score is not a real-world malware probability. Both included samples are harmless.
Only scan authorized, stable local files. Maximum file size: 5 MiB.

The code retains the PDF's prototype behavior, including its documented limitation
that file validation is not hardened against concurrent path replacement.
