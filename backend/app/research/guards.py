"""Local research guards: no network, credential, or upload surface."""
from __future__ import annotations

import os
import re
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Mapping

FORBIDDEN_ENV_NAMES = frozenset({
    "KAGGLE_API_TOKEN",
    "KAGGLE_USERNAME",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
})
FORBIDDEN_PATH_FRAGMENTS = (".kaggle", "kaggle.json", "credentials", "cloud")
FORBIDDEN_UPLOAD_WORDS = ("kaggle.api", "dataset_create", "upload_file", "boto3", "google.cloud")


class NetworkDisabled(RuntimeError):
    pass


class UploadDisabled(RuntimeError):
    pass


def safe_environment(environ: Mapping[str, str] | None = None, *, allow: Iterable[str] = ()) -> dict[str, str]:
    """Return only an explicit allowlist; credential names are never copied."""
    source = environ if environ is not None else os.environ
    allowed = set(allow)
    return {key: value for key, value in source.items() if key in allowed and key not in FORBIDDEN_ENV_NAMES}


def assert_no_forbidden_source(paths: Iterable[str | Path]) -> None:
    """Reject research source that references credential or upload surfaces."""
    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        lowered = text.lower()
        if any(word.lower() in lowered for word in FORBIDDEN_UPLOAD_WORDS):
            raise AssertionError(f"research source contains an upload client: {Path(path).name}")
        if any(fragment.lower() in lowered for fragment in FORBIDDEN_PATH_FRAGMENTS):
            raise AssertionError(f"research source contains a credential path: {Path(path).name}")


def assert_safe_local_path(path: str | Path, *, root: str | Path) -> Path:
    candidate = Path(path).resolve()
    base = Path(root).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError("research output must remain under the local root")
    lowered = str(candidate).lower()
    if any(fragment in lowered for fragment in FORBIDDEN_PATH_FRAGMENTS):
        raise ValueError("credential/cloud paths are not research inputs")
    return candidate


@contextmanager
def network_disabled():
    """Make accidental socket connections fail during a local smoke run."""
    original_socket = socket.socket
    original_create_connection = socket.create_connection

    class BlockedSocket(original_socket):
        def __new__(cls, *_args, **_kwargs):
            raise NetworkDisabled("network is disabled for local research")

    def blocked_connection(*_args, **_kwargs):
        raise NetworkDisabled("network is disabled for local research")

    socket.socket = BlockedSocket
    socket.create_connection = blocked_connection  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create_connection


def reject_upload(*_args, **_kwargs):
    raise UploadDisabled("research smoke has no upload operation")


__all__ = [
    "FORBIDDEN_ENV_NAMES",
    "NetworkDisabled",
    "UploadDisabled",
    "assert_no_forbidden_source",
    "assert_safe_local_path",
    "network_disabled",
    "reject_upload",
    "safe_environment",
]
