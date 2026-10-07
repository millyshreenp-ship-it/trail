"""Export an allowlisted private research archive; no upload operation."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def package(destination: Path) -> dict:
    destination = destination.resolve()
    if ROOT not in destination.parents:
        raise ValueError("output must remain inside the repository")
    sources = sorted((ROOT / "backend" / "app").rglob("*.py"))
    sources += [ROOT / "requirements-py312.lock", ROOT / "research" / "kaggle" / "run.py"]
    manifest = {"data_status": "synthetic", "external_data": False, "automatic_upload": False, "files": {}}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sources:
            name = source.relative_to(ROOT).as_posix()
            payload = source.read_bytes()
            manifest["files"][name] = hashlib.sha256(payload).hexdigest()
            archive.writestr(name, payload)
        archive.writestr("bundle-manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return {"path": str(destination), "files": len(sources), "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "evaluation" / "earlytrace-private.zip")
    print(json.dumps(package(parser.parse_args().out)))