"""
similarity.py
Three set-similarity metrics applied to Bloom-filter bit vectors.

All three metrics operate on pre-computed beta vectors (lists of 0/1 integers)
and return a float in [0, 1]. Jaccard is the primary decision metric;
Dice and Cosine are computed for reference / display purposes only.
"""

import math


JACCARD_THRESHOLD = 0.40


def _ones(beta):
    return sum(beta)


def _common(beta1, beta2):
    return sum(a & b for a, b in zip(beta1, beta2))


def jaccard(beta1, beta2):
    gamma = _common(beta1, beta2)
    k1 = _ones(beta1)
    k2 = _ones(beta2)
    denominator = k1 + k2 - gamma
    return gamma / denominator if denominator > 0 else 0.0


def dice(beta1, beta2):
    gamma = _common(beta1, beta2)
    k1 = _ones(beta1)
    k2 = _ones(beta2)
    denominator = k1 + k2
    return (2 * gamma) / denominator if denominator > 0 else 0.0


def cosine(beta1, beta2):
    gamma = _common(beta1, beta2)
    k1 = _ones(beta1)
    k2 = _ones(beta2)
    denominator = math.sqrt(k1) * math.sqrt(k2)
    return gamma / denominator if denominator > 0 else 0.0


def all_metrics(beta1, beta2):
    """Return (jaccard, dice, cosine) for a pair of beta vectors in one pass."""
    gamma = 0
    k1 = 0
    k2 = 0

    for a, b in zip(beta1, beta2):
        gamma += a & b
        k1 += a
        k2 += b

    j_denominator = k1 + k2 - gamma
    d_denominator = k1 + k2
    c_denominator = math.sqrt(k1 * k2) if k1 * k2 > 0 else 0

    return (
        gamma / j_denominator if j_denominator > 0 else 0.0,
        (2 * gamma) / d_denominator if d_denominator > 0 else 0.0,
        gamma / c_denominator if c_denominator > 0 else 0.0
    )
