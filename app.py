"""
app.py
Flask web server for the CSCI_262_project_GROUP19 Password Similarity Checker.

Routes
------
GET  /                     Serve the single-page HTML UI.
POST /check                Accept a JSON password (+ optional threshold), run the
                            Bloom-filter comparison, return the full JUSTIF table,
                            bigram/atom breakdown, and verdict as JSON.
GET  /bloom/<int>          Return the Bloom filter bit-vector for the nth dataset entry.
GET  /dataset/stats        Current dataset statistics (count, avg length, occupancy...).
GET  /dataset/global-bloom Bitwise OR of every password's beta -- the dataset-wide filter.
POST /dataset/reload       Reload dataset.txt from disk.
POST /dataset/upload       Replace the in-memory dataset with an uploaded word list.
POST /threshold/optimize   Empirically search for the best-separating Jaccard threshold.
"""

import os
import random
from flask import Flask, render_template, request, jsonify

from bloom_filter import compute_beta, compute_beta_detailed, L, K
from similarity import jaccard, dice, cosine, JACCARD_THRESHOLD

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB cap on uploaded datasets

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATASET_PATH = os.path.join(SCRIPT_DIR, "dataset.txt")
MAX_PASSWORD_LEN = 10

_LEET_MAP = {'o': '0', 'i': '1', 'e': '3', 'a': '4', 's': '5', 'l': '1'}

# Mutable app state, rebuilt whenever a dataset is (re)loaded. Kept as a single
# dict (rather than scattered globals) so set_dataset() can swap it atomically.
state = {
    "database": [],          # list of (password, beta) tuples
    "filename": "dataset.txt",
    "global_beta": [0] * L,  # bitwise OR of every password's beta -- dataset-wide filter
}


# ── Dataset loading ──────────────────────────────────────────────────────────

def load_passwords_from_text(text):
    """Parse raw dataset text and return only passwords that are 8-10 characters."""
    passwords = []
    for line in text.splitlines():
        p = line.strip()
        if 8 <= len(p) <= MAX_PASSWORD_LEN:
            passwords.append(p)
    return passwords


def load_passwords(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return load_passwords_from_text(fh.read())


def build_database(passwords):
    """Pre-compute beta(p) for every password once, so /check needs no hashing."""
    return [(p, compute_beta(p)) for p in passwords]


def compute_global_beta(database):
    """OR every password's beta together -- the classic single-filter Bloom
    membership vector for the whole dataset (used for the dataset-wide
    visualization, occupancy rate, and false-positive estimate)."""
    beta = [0] * L
    for _, b in database:
        for i, bit in enumerate(b):
            if bit:
                beta[i] = 1
    return beta


def set_dataset(passwords, filename):
    """Replace the in-memory dataset and recompute every derived structure."""
    database = build_database(passwords)
    state["database"] = database
    state["filename"] = filename
    state["global_beta"] = compute_global_beta(database)
    print(f"[*] Loaded {len(database)} passwords from {filename}.")


def init_db():
    passwords = load_passwords(DEFAULT_DATASET_PATH)
    set_dataset(passwords, "dataset.txt")


def dataset_stats():
    database = state["database"]
    count = len(database)
    lengths = [len(p) for p, _ in database]
    avg_len = round(sum(lengths) / count, 2) if count else 0
    unique_count = len(set(p for p, _ in database))
    bits_set = sum(state["global_beta"])
    occupancy = bits_set / L
    return {
        "filename": state["filename"],
        "count": count,
        "avg_length": avg_len,
        "unique_count": unique_count,
        "bits_set": bits_set,
        "occupancy_rate": round(occupancy, 4),
        "fp_estimate": round(occupancy ** K, 6),
        "L": L,
        "K": K,
    }


# ── Threshold optimizer helpers ──────────────────────────────────────────────

def _mutate_password(password):
    """Return a single-edit 'tweaked' variant of password, or None if impossible.

    Mirrors the kinds of small edits real users make when dodging a password
    policy: a leetspeak substitution, a case flip, an appended digit, or an
    adjacent transposition -- in that preference order.
    """
    chars = list(password)

    for i, ch in enumerate(chars):
        low = ch.lower()
        if low in _LEET_MAP:
            chars[i] = _LEET_MAP[low]
            return ''.join(chars)

    for i, ch in enumerate(chars):
        if ch.isalpha():
            chars[i] = ch.lower() if ch.isupper() else ch.upper()
            return ''.join(chars)

    if len(password) < MAX_PASSWORD_LEN:
        return password + '9'

    if len(password) >= 2:
        chars[-1], chars[-2] = chars[-2], chars[-1]
        return ''.join(chars)

    return None


def _metrics_at(threshold, similar_scores, different_scores):
    """Confusion-matrix metrics treating 'similar pair' as the positive class."""
    tp = sum(1 for s in similar_scores if s >= threshold)
    fn = len(similar_scores) - tp
    fp = sum(1 for s in different_scores if s >= threshold)
    tn = len(different_scores) - fp
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1, tp, fp, tn, fn


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main UI, injecting dataset/threshold context into the template."""
    stats = dataset_stats()
    return render_template(
        "index.html",
        db_size=stats["count"],
        threshold=JACCARD_THRESHOLD,
        dataset_filename=stats["filename"],
        L=L,
        K=K,
    )


@app.route("/check", methods=["POST"])
def check():
    """Compare the submitted password against every entry in the database.

    Algorithm
    ---------
    1. Validate length (8-10 characters).
    2. Compute beta(candidate) with the full per-bigram atom breakdown.
    3. Score every dataset entry with Jaccard, Dice, and Cosine.
    4. Track the best Jaccard match for the verdict.
    5. Sort all rows by Jaccard descending -- this is the JUSTIF table.
    6. Apply the (optionally client-supplied) threshold to produce ACCEPT / REJECT.

    Returns JSON with the full JUSTIF table, verdict, bigram/atom detail, and
    both the candidate's and the closest match's full 1000-bit vectors (for
    the shared-bit comparison view).
    """
    data = request.get_json(silent=True) or {}
    candidate = (data.get("password") or "").strip()

    try:
        threshold = float(data.get("threshold", JACCARD_THRESHOLD))
    except (TypeError, ValueError):
        threshold = JACCARD_THRESHOLD
    threshold = min(max(threshold, 0.0), 1.0)

    if len(candidate) < 8:
        return jsonify({"error": "Password must be at least 8 characters."})
    if len(candidate) > MAX_PASSWORD_LEN:
        return jsonify({"error": "Password must be at most 10 characters."})

    detail = compute_beta_detailed(candidate)
    beta_c = detail["beta"]
    beta_full = "".join(str(b) for b in beta_c)
    bits_set = sum(beta_c)

    atoms = [{
        "bigram": a["bigram"],
        "sha256": a["sha256"],
        "md5": a["md5"],
        "positions": a["positions"],
        "bits_set": a["bits_set"],
    } for a in detail["atoms"]]

    database = state["database"]
    all_rows = []
    best_j, best_d, best_c, best_match = 0.0, 0.0, 0.0, None
    best_gamma, best_k2, best_beta_s = 0, 0, None

    for (stored, beta_s) in database:
        j = jaccard(beta_c, beta_s)
        d = dice(beta_c, beta_s)
        c = cosine(beta_c, beta_s)
        all_rows.append({
            "password": stored,
            "jaccard": round(j, 4),
            "dice": round(d, 4),
            "cosine": round(c, 4),
        })
        if j > best_j:
            best_j, best_d, best_c, best_match = j, d, c, stored
            best_gamma = sum(a & b for a, b in zip(beta_c, beta_s))
            best_k2 = sum(beta_s)
            best_beta_s = beta_s

    all_rows.sort(key=lambda r: r["jaccard"], reverse=True)
    reject = best_j >= threshold
    best_beta_full = "".join(str(b) for b in best_beta_s) if best_beta_s else "0" * L

    return jsonify({
        "reject":        reject,
        "best_match":    best_match,
        "jaccard":       round(best_j, 4),
        "dice":          round(best_d, 4),
        "cosine":        round(best_c, 4),
        "gamma":         best_gamma,
        "k1":            bits_set,
        "k2":            best_k2,
        "bigrams":       detail["bigrams"],
        "padded":        detail["padded"],
        "atoms":         atoms,
        "beta_full":     beta_full,
        "best_beta_full": best_beta_full,
        "threshold":     threshold,
        "all_rows":      all_rows,      # full JUSTIF table for the UI
    })


@app.route("/bloom/<int:index>")
def bloom_entry(index):
    """Return the full Bloom filter for the nth dataset entry (1-based index).

    Used by the UI's Bloom Filter Viewer to display and screenshot individual
    entries -- specifically entries #17 and #55 required by the assignment.
    """
    database = state["database"]
    if index < 1 or index > len(database):
        return jsonify({"error": f"Index must be between 1 and {len(database)}."})

    password, beta = database[index - 1]
    return jsonify({
        "index":    index,
        "password": password,
        "bits_set": sum(beta),
        "beta":     "".join(str(b) for b in beta),   # full 1000-bit string
    })


@app.route("/dataset/stats")
def dataset_stats_route():
    return jsonify(dataset_stats())


@app.route("/dataset/global-bloom")
def dataset_global_bloom():
    """The dataset-wide Bloom filter: bitwise OR of every stored password's beta."""
    beta = state["global_beta"]
    bits_set = sum(beta)
    occupancy = bits_set / L
    return jsonify({
        "beta":           "".join(str(b) for b in beta),
        "bits_set":       bits_set,
        "occupancy_rate": round(occupancy, 4),
        "fp_estimate":    round(occupancy ** K, 6),
        "L": L,
        "K": K,
    })


@app.route("/dataset/reload", methods=["POST"])
def dataset_reload():
    """Reload dataset.txt from disk, discarding any uploaded dataset."""
    try:
        passwords = load_passwords(DEFAULT_DATASET_PATH)
    except OSError as exc:
        return jsonify({"error": f"Could not read dataset.txt: {exc}"})
    if not passwords:
        return jsonify({"error": "dataset.txt contains no 8-10 character passwords."})
    set_dataset(passwords, "dataset.txt")
    return jsonify(dataset_stats())


@app.route("/dataset/upload", methods=["POST"])
def dataset_upload():
    """Replace the in-memory dataset with an uploaded word list (one password
    per line). The uploaded file is never written to disk, so dataset.txt --
    the file the assignment is graded against -- is always left untouched.
    Use /dataset/reload to return to it."""
    file = request.files.get("file")
    if file is None or file.filename == "":
        return jsonify({"error": "No file selected."})

    try:
        raw = file.read().decode("utf-8", errors="ignore")
    except Exception:
        return jsonify({"error": "Could not read the uploaded file as text."})

    passwords = load_passwords_from_text(raw)
    if not passwords:
        return jsonify({"error": "No 8-10 character passwords found in the uploaded file."})

    set_dataset(passwords, file.filename)
    return jsonify(dataset_stats())


@app.route("/threshold/optimize", methods=["POST"])
def threshold_optimize():
    """Empirically search for the Jaccard threshold that best separates
    'similar / tweaked' password pairs from 'different / unrelated' pairs,
    sampled from the currently loaded dataset.

    Method
    ------
    1. Sample up to 20 dataset passwords.
    2. Build a 'similar' pair for each by applying one realistic mutation
       (leetspeak substitution, case flip, appended digit, or transposition).
    3. Build a 'different' pair for each by matching it against the next
       password in a shuffled ring (guaranteed distinct strings).
    4. Score every pair with Jaccard, then evaluate every midpoint between
       adjacent observed scores as a candidate threshold, picking the one
       that maximises F1 (similar pair = positive class = "should reject").
    """
    database = state["database"]
    if len(database) < 4:
        return jsonify({"error": "Dataset too small to run threshold analysis."})

    sample_n = min(20, len(database))
    rng = random.Random(1234)  # deterministic sample -- repeated clicks agree
    sample = rng.sample(database, sample_n)

    similar_scores = []
    for pwd, beta_orig in sample:
        tweaked = _mutate_password(pwd)
        if tweaked and tweaked != pwd:
            similar_scores.append(jaccard(beta_orig, compute_beta(tweaked)))

    shuffled = sample[:]
    rng.shuffle(shuffled)
    different_scores = []
    for i in range(len(shuffled)):
        a_pwd, a_beta = shuffled[i]
        b_pwd, b_beta = shuffled[(i + 1) % len(shuffled)]
        if a_pwd != b_pwd:
            different_scores.append(jaccard(a_beta, b_beta))

    if not similar_scores or not different_scores:
        return jsonify({"error": "Could not build enough test pairs from the current dataset."})

    all_scores = sorted(set(similar_scores + different_scores))
    candidates = [0.0] + [
        (all_scores[i] + all_scores[i + 1]) / 2 for i in range(len(all_scores) - 1)
    ] + [1.0]

    best_t, best_f1, best_metrics = JACCARD_THRESHOLD, -1.0, None
    for t in candidates:
        precision, recall, f1, tp, fp, tn, fn = _metrics_at(t, similar_scores, different_scores)
        if f1 > best_f1:
            best_t, best_f1, best_metrics = t, f1, (precision, recall, f1, tp, fp, tn, fn)

    precision, recall, f1, tp, fp, tn, fn = best_metrics
    gap_low = max(different_scores)
    gap_high = min(similar_scores)

    if gap_high > gap_low:
        reasoning = (
            f"The {len(different_scores)} sampled 'different' pairs score at most {gap_low:.4f}, "
            f"and the {len(similar_scores)} sampled 'similar/tweaked' pairs score at least "
            f"{gap_high:.4f}. Threshold {round(best_t, 4)} sits inside that "
            f"{gap_high - gap_low:.4f}-wide gap, giving perfect separation on this sample "
            f"(0 false positives, 0 false negatives)."
        )
    else:
        reasoning = (
            f"The 'different' and 'similar' score distributions overlap on this sample "
            f"(different max={gap_low:.4f}, similar min={gap_high:.4f}). Threshold "
            f"{round(best_t, 4)} was chosen to maximise F1 = {f1:.4f} "
            f"(precision={precision:.4f}, recall={recall:.4f})."
        )

    return jsonify({
        "recommended_threshold": round(best_t, 4),
        "reasoning":             reasoning,
        "precision":             round(precision, 4),
        "recall":                round(recall, 4),
        "f1":                    round(f1, 4),
        "confusion":             {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "similar_count":         len(similar_scores),
        "different_count":       len(different_scores),
        "similar_min":           round(min(similar_scores), 4),
        "similar_max":           round(max(similar_scores), 4),
        "different_min":         round(min(different_scores), 4),
        "different_max":         round(max(different_scores), 4),
    })


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
