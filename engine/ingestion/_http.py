"""Shared HTTP helpers with retry/backoff. Ingestion never parses semantics; it only fetches and stores RAW."""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path

import requests

from engine.config import settings

RETRY_STATUSES = {403, 429, 500, 502, 503, 504}


def get(url: str, *, headers: dict | None = None, params: dict | None = None, stream: bool = False,
        max_retries: int = settings.NVD_MAX_RETRIES) -> requests.Response:
    h = {"User-Agent": settings.USER_AGENT}
    if headers:
        h.update(headers)
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, headers=h, params=params, timeout=settings.HTTP_TIMEOUT, stream=stream)
            if r.status_code == 200:
                return r
            if r.status_code in RETRY_STATUSES:
                wait = min(60, 5 * 2 ** (attempt - 1))
                print(f"  [http] {r.status_code} on attempt {attempt}; sleeping {wait}s")
                time.sleep(wait)
                continue
            r.raise_for_status()
        except requests.RequestException as exc:  # network errors
            last_exc = exc
            wait = min(60, 5 * 2 ** (attempt - 1))
            print(f"  [http] {exc.__class__.__name__} on attempt {attempt}; sleeping {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"GET failed after {max_retries} attempts: {url}") from last_exc


def write_json_gz(obj: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


def read_json_gz(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def write_bytes(data: bytes, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path
