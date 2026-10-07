# Local research smoke

This directory is a local, offline smoke path—not a Kaggle client and not a dataset upload workflow. It generates only a tiny `earlytrace-sim-2` fixture from the repository, writes local manifests/metrics, disables sockets during the run, and reports `smoke_only_insufficient_evidence`.

Run from `trail` with the project interpreter:

```powershell
& ".\.venv\Scripts\python.exe" research\kaggle\smoke.py
```

The smoke path does not read external datasets, credential files, cloud paths, or upload destinations. The ignored IEEE-CIS/Elliptic archives remain out of scope. Generated output under `research/kaggle/runs/` is local smoke output and is not a research result.
