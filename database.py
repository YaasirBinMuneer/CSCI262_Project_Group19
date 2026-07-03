"""
database.py
Shared dataset utilities used by both app.py (web server) and main.py (CLI).

Keeping these here avoids duplicating the parse+build logic across both entry
points. File I/O and error handling remain in each caller because the web
server and CLI have different failure modes (HTTP 500 vs sys.exit).
"""

from bloom_filter import compute_beta


def load_passwords_from_text(text, min_len=8, max_len=10):
    """Parse raw dataset text and return passwords within the length range."""
    passwords = []
    for line in text.splitlines():
        p = line.strip()
        if min_len <= len(p) <= max_len:
            passwords.append(p)
    return passwords


def build_database(passwords):
    """Pre-compute beta(p) for every password; returns (password, beta) tuples.

    Call once at startup — comparisons then need no hashing at query time.
    """
    return [(p, compute_beta(p)) for p in passwords]
