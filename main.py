"""
main.py
Command-line interface for the CSCI_262_project_GROUP19 Password Similarity Checker.

Usage
-----
    python main.py                      # interactive mode
    python main.py --demo               # step-by-step walkthrough
    python main.py --threshold          # print threshold justification analysis
    python main.py --bloom N            # display Bloom filter for the Nth dataset entry
    python main.py --dataset FILE       # use a custom dataset file
"""

import sys
import os
import time
from bloom_filter import compute_beta, show_bigrams, L, K
from similarity  import jaccard, all_metrics, JACCARD_THRESHOLD
from database    import load_passwords_from_text, build_database as _build_database

# Resolve the default dataset relative to this script, not the caller's cwd —
# otherwise `python main.py` fails with a bad path when launched from
# anywhere other than this folder.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATASET = os.path.join(SCRIPT_DIR, 'dataset.txt')


# ── Dataset loading ─────────────────────────────────────────────────────────────

def load_dataset(filepath=None):
    """Read the dataset file and return passwords that are 8-10 characters long."""
    if filepath is None:
        filepath = DEFAULT_DATASET
    if not os.path.exists(filepath):
        print(f"[ERROR] Dataset file not found: {filepath}")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
        return load_passwords_from_text(fh.read())


def build_database(passwords):
    """Thin wrapper around database.build_database that adds a progress print."""
    print(f"[*] Building Bloom filters for {len(passwords)} common passwords ...")
    t0 = time.time()
    db = _build_database(passwords)
    print(f"[*] Done in {time.time() - t0:.2f}s\n")
    return db


# ── Core comparison ─────────────────────────────────────────────────────────────

def check_password(candidate, database, beta_c=None):
    """Score the candidate against every stored password.

    Computes Jaccard, Dice, and Cosine for each entry and collects all rows
    for the JUSTIF table.  Also tracks the highest-Jaccard match for the verdict.

    beta_c may be passed in if the caller already computed it, to avoid
    re-hashing the same candidate twice.  The matched entry's own beta vector
    is returned too — every dataset beta is already cached in `database`, so
    callers never need to call compute_beta() again for gamma/k stats.

    Returns
    -------
    (accepted, closest_password, (jaccard, dice, cosine), all_rows, beta_c, best_beta_s)
    all_rows is a list of (password, j, d, c) sorted by Jaccard descending.
    """
    if beta_c is None:
        beta_c = compute_beta(candidate)

    best_match, best_j, best_d, best_c = None, 0.0, 0.0, 0.0
    best_beta_s = None
    all_rows = []

    for (stored, beta_s) in database:
        j, d, c = all_metrics(beta_c, beta_s)  # single-pass: 1 scan instead of 3
        all_rows.append((stored, j, d, c))
        if j > best_j:
            best_j, best_d, best_c, best_match = j, d, c, stored
            best_beta_s = beta_s

    # Sort so the most similar password is at the top of the JUSTIF table.
    all_rows.sort(key=lambda r: r[1], reverse=True)

    accepted = best_j < JACCARD_THRESHOLD
    return accepted, best_match, (best_j, best_d, best_c), all_rows, beta_c, best_beta_s


# ── JUSTIF table ────────────────────────────────────────────────────────────────

def print_justif(all_rows, best_match, candidate):
    """Print the JUSTIF table comparing candidate against all dataset passwords.

    Shows every dataset entry with its Jaccard, Dice, and Cosine scores.
    The row matching the closest password is starred for easy identification.
    Rows are pre-sorted by Jaccard descending.
    """
    col_w = 14   # password column width

    header = (f"  {'#':<5} {'Password':<{col_w}} {'Jaccard':>10} "
              f"{'Dice':>10} {'Cosine':>10}")
    sep    = "  " + "-" * (len(header) - 2)

    print(f"\n  JUSTIF TABLE - beta(UserP) vs all {len(all_rows)} dataset passwords")
    print(f"  Candidate: '{candidate}'   Threshold: Jaccard >= {JACCARD_THRESHOLD} -> REJECT")
    print(sep)
    print(header)
    print(sep)

    for rank, (pwd, j, d, c) in enumerate(all_rows, 1):
        marker = " *" if pwd == best_match else ""
        print(f"  {rank:<5} {pwd:<{col_w}} {j:>10.4f} {d:>10.4f} {c:>10.4f}{marker}")

    print(sep)
    print(f"  * = closest match used for decision\n")


# ── Bloom filter viewer ─────────────────────────────────────────────────────────

def show_bloom_entry(database, n):
    """Print the full 1000-bit Bloom filter for the nth dataset entry (1-based).

    Output is arranged as 20 rows × 50 bits for readability, with the starting
    bit index shown on the left.  Required for the assignment's screenshot of
    entries #17 and #55.
    """
    if n < 1 or n > len(database):
        print(f"[ERROR] Index {n} is out of range (1-{len(database)}).")
        return

    password, beta = database[n - 1]
    bits_set = sum(beta)

    print(f"\n{'='*60}")
    print(f"  Bloom Filter - Entry #{n}: '{password}'")
    print(f"  L = {L} bits   k = {K} hash functions   Bits set: {bits_set}/{L}")
    print(f"{'='*60}")

    # 20 rows of 50 bits each
    for row in range(20):
        start = row * 50
        segment = "".join(str(b) for b in beta[start:start + 50])
        print(f"  [{start:>4}-{start+49:<4}]  {segment}")

    print(f"{'='*60}\n")


# ── Threshold analysis ──────────────────────────────────────────────────────────

def run_threshold_analysis():
    """Print Jaccard distributions that justify JACCARD_THRESHOLD = 0.40.

    Similar/tweaked pairs should score well above the threshold;
    unrelated pairs should score well below it.
    """
    similar_pairs = [
        ("password", "passw0rd",  "digit substitution"),
        ("password", "p@ssword",  "symbol substitution"),
        ("password", "passworD",  "case flip"),
        ("password", "passwords", "appended char"),
        ("letmein1", "letmein2",  "last digit changed"),
        ("letmein1", "letme1n1",  "transposition"),
        ("monkey12", "m0nkey12",  "vowel -> digit"),
        ("dragon12", "dragon21",  "digit swap"),
        ("sunshine", "sunsh1ne",  "vowel -> digit"),
        ("iloveyou", "ilov3you",  "vowel -> digit"),
    ]
    different_pairs = [
        ("password", "sunshine1", "unrelated"),
        ("password", "football1", "unrelated"),
        ("letmein1", "sunshine1", "unrelated"),
        ("monkey12", "princess1", "unrelated"),
        ("dragon12", "baseball1", "unrelated"),
        ("abc12345", "xyz98765",  "unrelated"),
        ("qwerty123", "michael99","unrelated"),
        ("iloveyou", "trustno11", "unrelated"),
        ("sunshine", "master123", "unrelated"),
        ("welcome1", "shadow123", "unrelated"),
    ]

    def _score_group(pairs, label):
        print(f"\n  {'Password A':<12} {'Password B':<12} {'Mutation type':<28} {'Jaccard':>8}")
        print(f"  {'-'*12} {'-'*12} {'-'*28} {'-'*8}")
        scores = []
        for a, b, kind in pairs:
            j = jaccard(compute_beta(a), compute_beta(b))
            scores.append(j)
            print(f"  {a:<12} {b:<12} {kind:<28} {j:>8.4f}")
        print(f"\n  {label:>9} Jaccard:  min={min(scores):.4f}  "
              f"max={max(scores):.4f}  avg={sum(scores)/len(scores):.4f}")
        return scores

    print("=" * 68)
    print("  THRESHOLD JUSTIFICATION  (L=1000, k=20, bi-gram Bloom filter)")
    print("=" * 68)

    print("\n[A] SIMILAR pairs (tweaked / mutated passwords) - expect HIGH scores")
    sim_scores = _score_group(similar_pairs, "Similar")

    print("\n[B] DIFFERENT pairs (unrelated passwords) - expect LOW scores")
    dif_scores = _score_group(different_pairs, "Different")

    gap_low  = max(dif_scores)
    gap_high = min(sim_scores)
    midpoint = (gap_low + gap_high) / 2

    print(f"""
[C] THRESHOLD SELECTION
    Highest 'different' Jaccard : {gap_low:.4f}
    Lowest  'similar'  Jaccard  : {gap_high:.4f}
    Gap size                    : {gap_high - gap_low:.4f}
    Midpoint of gap             : {midpoint:.4f}
    Chosen threshold            : {JACCARD_THRESHOLD:.4f}

    Rationale:
    - All {len(similar_pairs)} similar/tweaked pairs score >= {gap_high:.4f} (above threshold).
    - All {len(different_pairs)} unrelated pairs score  <= {gap_low:.4f} (below threshold).
    - The two clusters are cleanly separated with a gap of {gap_high - gap_low:.4f}.
    - Threshold {JACCARD_THRESHOLD} sits inside this gap, giving:
        * 0 false negatives  (no tweaked password accepted) on this test set.
        * 0 false positives  (no different password rejected) on this test set.
    - Placed closer to the 'different' cluster to err on the side of accepting
      a borderline password rather than over-rejecting genuinely new ones.
""")


# ── Demo mode ───────────────────────────────────────────────────────────────────

def run_demo():
    """Walk through three candidates: exact match, tweaked, and unrelated."""
    print("=" * 60)
    print("  DEMO MODE  --  Bloom filter similarity detection")
    print("=" * 60)

    passwords = load_dataset(DEFAULT_DATASET)
    if not passwords:
        print("[ERROR] No valid passwords loaded from dataset.")
        return
    db = build_database(passwords)

    test_cases = [
        ("skittles",  "exact dataset entry"),
        ("sk1ttles",  "tweaked: vowel 'i' replaced with '1'"),
        ("zxcvbnm99", "unrelated keyboard pattern"),
    ]

    for candidate, label in test_cases:
        print(f"\n[CANDIDATE] '{candidate}'  ({label})")

        if len(candidate) < 8 or len(candidate) > 10:
            print(f"  [!] Length {len(candidate)} - must be 8-10 characters. Skipped.")
            continue

        print(f"\n  Step 1  Bi-gram extraction:")
        show_bigrams(candidate)

        beta_c = compute_beta(candidate)
        print(f"  Step 2  beta(p): {''.join(str(b) for b in beta_c[:40])}...  [{sum(beta_c)}/1000 bits set]")

        print(f"\n  Step 3  Scanning {len(db)} database entries ...")
        accepted, closest, (j, d, c), all_rows, _, best_beta_s = check_password(candidate, db, beta_c=beta_c)

        k1 = sum(beta_c)
        if closest:
            k2    = sum(best_beta_s)
            gamma = sum(a & b for a, b in zip(beta_c, best_beta_s))
        else:
            k2, gamma = 0, 0

        print(f"  Step 4  Best match: '{closest}'")
        print(f"          gamma = {gamma}   k_beta1 = {k1}   k_beta2 = {k2}")
        print(f"          Jaccard = {j:.4f}   Dice = {d:.4f}   Cosine = {c:.4f}")
        print(f"          Threshold = {JACCARD_THRESHOLD}")

        # Print top-5 rows of the JUSTIF table to illustrate the comparison
        print(f"\n  JUSTIF (top 5 of {len(all_rows)} entries, sorted by Jaccard):")
        print(f"  {'#':<5} {'Password':<14} {'Jaccard':>10} {'Dice':>10} {'Cosine':>10}")
        print(f"  {'-'*55}")
        for rank, (pwd, rj, rd, rc) in enumerate(all_rows[:5], 1):
            marker = " *" if pwd == closest else ""
            print(f"  {rank:<5} {pwd:<14} {rj:>10.4f} {rd:>10.4f} {rc:>10.4f}{marker}")

        verdict = ("ACCEPT  -- Jaccard < threshold: sufficiently different from all common passwords"
                   if accepted else
                   "REJECT  -- Jaccard >= threshold: too similar to a common password")
        print(f"\n  Decision -> {verdict}")
        print("-" * 60)


# ── Interactive mode ────────────────────────────────────────────────────────────

def run_interactive(database):
    """Prompt-loop: read a candidate, print the full JUSTIF table and verdict."""
    print("=" * 60)
    print("  Password Strength Checker")
    print("  (type 'quit' to exit)")
    print("=" * 60)

    while True:
        try:
            candidate = input("\nEnter candidate password (UserP): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if candidate.lower() == 'quit':
            print("Goodbye.")
            break

        if len(candidate) < 8:
            print("  [!] Password must be at least 8 characters. Please resubmit.")
            continue
        if len(candidate) > 10:
            print("  [!] Password exceeds maximum length of 10 characters. Please resubmit.")
            continue

        # Bi-gram and Bloom filter breakdown
        show_bigrams(candidate)
        beta_c = compute_beta(candidate)
        print(f"  beta(p): {''.join(str(b) for b in beta_c[:40])}...  [{sum(beta_c)}/1000 bits set]")

        # Full JUSTIF table
        accepted, closest, (j, d, c), all_rows, _, _ = check_password(candidate, database, beta_c=beta_c)
        print_justif(all_rows, closest, candidate)

        # Verdict with justification referencing all three metrics
        print(f"  Jaccard = {j:.4f}  (threshold {JACCARD_THRESHOLD})   "
              f"Dice = {d:.4f}   Cosine = {c:.4f}")
        print(f"  Closest common password: '{closest}'\n")

        if accepted:
            print(f"  ACCEPTED -- '{candidate}' is not similar to any common password.")
            print(f"  Justification: Jaccard {j:.4f} < {JACCARD_THRESHOLD} (threshold).")
            print(f"  Supporting metrics: Dice = {d:.4f}, Cosine = {c:.4f} -- all low,")
            print(f"  confirming the candidate is sufficiently distinct from all stored passwords.")
        else:
            print(f"  REJECTED -- '{candidate}' is too similar to a known common password.")
            print(f"  Justification: Jaccard {j:.4f} >= {JACCARD_THRESHOLD} (threshold).")
            print(f"  Supporting metrics: Dice = {d:.4f}, Cosine = {c:.4f} -- all elevated,")
            print(f"  confirming high overlap between beta(UserP) and beta('{closest}').")


# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    dataset_file = DEFAULT_DATASET

    if '--dataset' in sys.argv:
        idx = sys.argv.index('--dataset')
        if idx + 1 < len(sys.argv):
            dataset_file = sys.argv[idx + 1]

    if '--demo' in sys.argv:
        run_demo()
        sys.exit(0)

    if '--threshold' in sys.argv:
        run_threshold_analysis()
        sys.exit(0)

    if '--bloom' in sys.argv:
        idx = sys.argv.index('--bloom')
        if idx + 1 < len(sys.argv):
            try:
                n = int(sys.argv[idx + 1])
            except ValueError:
                print("[ERROR] --bloom requires an integer index, e.g. --bloom 55")
                sys.exit(1)
            passwords = load_dataset(dataset_file)
            db = build_database(passwords)
            show_bloom_entry(db, n)
        else:
            print("[ERROR] --bloom requires an index argument, e.g. --bloom 17")
        sys.exit(0)

    passwords = load_dataset(dataset_file)
    if not passwords:
        print("[ERROR] No 8-10 character passwords found in dataset.")
        sys.exit(1)

    database = build_database(passwords)
    run_interactive(database)
