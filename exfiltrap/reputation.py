"""Domain reputation guard — the popular-domain safety net for responses.

Any automated response that edits DNS state (the 0.0.0.0 sinkhole) needs a
hard guarantee that the Internet's infrastructure can never be caught in a
false positive: sinking google.com does not "block the attacker", it takes
the operator's own machine offline. This module answers one question —
``is_popular(qname)`` — from two sources:

1. The Tranco top-sites sample shipped in ``data/`` (rank, domain CSV —
   the same corpus the benign generator uses, so "popular" means the same
   thing on both sides of the evaluation).
2. A small built-in list of must-never-touch infrastructure (resolver
   zones, OS update hosts) that holds even if the CSV is missing.

Membership checks the full qname AND its base domain: a flagged label
under a popular base domain (``fonts.gstatic.com`` with whatever random
sub-label) is still popular infrastructure.
"""

from __future__ import annotations

import csv
import os
import threading

from exfiltrap import config

# Even with no Tranco file at all, these can never be responded against.
_BUILTIN = frozenset({
    # name resolution / identity infrastructure
    "localhost", "ip6-localhost", "ip6-loopback", "local", "lan", "internal",
    "in-addr.arpa", "ip6.arpa", "home.arpa", "invalid", "localdomain",
    "workgroup", "arpa", "test", "example", "example.com", "example.net",
    "example.org",
    # the biggest OS / browser / CDN endpoints (belt and braces)
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windowsupdate.com", "microsoftonline.com", "live.com",
    "office.com", "msn.com", "bing.com", "apple.com", "icloud.com",
    "cloudflare.com", "amazonaws.com", "amazon.com", "akamai.com",
    "akamaiedge.net", "fastly.net", "cloudfront.net", "ubuntu.com",
    "debian.org", "kernel.org", "mozilla.org", "firefox.com", "kali.org",
})

_lock = threading.Lock()
_popular: set[str] | None = None


def _load_csv(path: str) -> set[str]:
    found: set[str] = set()
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and row[1].strip():
                    found.add(row[1].strip().lower())
    except OSError:
        pass
    return found


def _load() -> set[str]:
    global _popular
    with _lock:
        if _popular is None:
            domains = set(_BUILTIN)
            domains |= _load_csv(config.TRANCO_CSV)
            _popular = domains
        return _popular


def reload(path: str | None = None) -> int:
    """Force a (re)load — returns the corpus size. Used by tests."""
    global _popular
    with _lock:
        domains = set(_BUILTIN)
        if path is not None:
            domains |= _load_csv(path)
        else:
            domains |= _load_csv(config.TRANCO_CSV)
        _popular = domains
        return len(domains)


def is_popular(qname: str) -> bool:
    """True when the qname or its base domain is known-popular infra."""
    q = (qname or "").strip().lower().rstrip(".")
    if not q:
        return False
    corpus = _load()
    if q in corpus:
        return True
    labels = q.split(".")
    if len(labels) > 2:
        return ".".join(labels[-2:]) in corpus
    return False


def corpus_size() -> int:
    return len(_load())
