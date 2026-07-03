"""
bloom_filter.py
Builds a Bloom-filter bit-vector (beta) for a given password using bi-gram
hashing.  No password text is ever stored — only the resulting bit pattern.
"""

import hashlib

# Assignment-specified parameters
L = 1000   # length of each bit vector
K = 20     # number of hash functions (h_0 … h_{K-1})


def get_bigrams(password):
    """Return all consecutive character pairs from the space-padded password.

    A leading/trailing space is added so that the first and last characters
    each contribute a bigram that encodes their boundary position, not just
    their identity.  E.g. "cat" → " cat " → [' c','ca','at','t '].
    """
    padded = ' ' + password + ' '
    return [padded[i:i+2] for i in range(len(padded) - 1)]


def compute_beta(password):
    """Compute the 1 000-bit Bloom filter vector beta(p) for a password.

    Thin wrapper around compute_beta_detailed() — see that function for the
    full per-bigram/atom breakdown used by the web UI.
    """
    return compute_beta_detailed(password)['beta']


def compute_beta_detailed(password):
    """Compute beta(p) and return the full per-bigram atom breakdown.

    For every bi-gram b extracted from the padded password:
      - f = SHA-256(b) as a big integer  (primary hash)
      - g = MD5(b)     as a big integer  (mixing term)
      - h_i(b) = (f + i * g) mod L       for i = 0 … K-1

    This is the standard double-hashing trick: one pair (f, g) generates K
    independent-looking positions without needing K separate hash calls.

    Each bi-gram's own set of positions is called an "atom". The final beta
    vector is the bitwise OR of all atoms — once a bit is set to 1 it can
    never go back to 0 within the same password.

    Returns
    -------
    {
        "padded":  " password ",
        "bigrams": ["_p", "pa", ...],
        "atoms": [
            {
                "bigram":    "_p",
                "sha256":    "<64-hex f>",
                "md5":       "<32-hex g>",
                "positions": [24, 103, 211, ...],   # up to K positions (may collide)
                "bits_set":  20,                    # unique positions actually set
            },
            ...
        ],
        "beta": [0, 1, 0, ...],   # length-L OR of all atoms
    }
    """
    padded = ' ' + password + ' '
    bigrams = get_bigrams(password)
    beta = [0] * L
    atoms = []

    for bigram in bigrams:
        encoded = bigram.encode('utf-8')
        sha256_hex = hashlib.sha256(encoded).hexdigest()
        md5_hex = hashlib.md5(encoded).hexdigest()
        f = int(sha256_hex, 16)  # primary hash
        g = int(md5_hex, 16)     # mixing hash

        positions = []
        for i in range(K):
            pos = (f + i * g) % L   # double-hashing: one position per round
            positions.append(pos)
            beta[pos] = 1            # OR: set bit (idempotent)

        atoms.append({
            'bigram': bigram,
            'sha256': sha256_hex,
            'md5': md5_hex,
            'positions': positions,
            'bits_set': len(set(positions)),
        })

    return {'padded': padded, 'bigrams': bigrams, 'atoms': atoms, 'beta': beta}


def show_bigrams(password):
    """Print the bi-gram decomposition for a password (CLI demo helper)."""
    bigrams = get_bigrams(password)
    padded = ' ' + password + ' '
    print(f"  Padded string : '{padded}'")
    print(f"  Bi-grams ({len(bigrams)}) : {bigrams}")
    return bigrams
