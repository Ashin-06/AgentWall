"""Evaluate Layer 3 configurations: heuristics, classifier, LLM, classifier + LLM.

  python evals/classifier_eval.py --split dev                    # threshold sweep (tuning)
  python evals/classifier_eval.py --split test --threshold T     # held-out report

Classifier and heuristic scores are computed here. LLM scores and latencies are read from the
per-row results of evals/ml_eval.py (evals/results/<split>-<model>.json, same frozen rows, same
production prompt), so the slow LLM pass is not repeated. Combination uses the production
function agentwall.layer3.classifier.combine.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evals"))

from ml_eval import DATA, RESULTS, metrics, to_call  # noqa: E402
from agentwall.layer1.normaliser import normalise_text  # noqa: E402
from agentwall.layer3._heuristics import heuristic_score  # noqa: E402
from agentwall.layer3.classifier import BLOCK_SCORE, InjectionClassifier, combine, to_score  # noqa: E402
from agentwall.layer3.injection import LLMInjectionClassifier  # noqa: E402

MODELS = ("llama3.2_3b", "llama3.1_latest")


def score_rows(rows, clf):
    out = []
    for row in rows:
        text = LLMInjectionClassifier._collect_text(to_call(row))
        t0 = time.perf_counter()
        prob = clf.probability(text)
        ms = (time.perf_counter() - t0) * 1000
        h, _ = heuristic_score(normalise_text(text))
        out.append({"label": row["label"], "source": row["source"], "clf_prob": prob, "clf_ms": ms, "heuristic": h})
    return out


def lat(values):
    v = sorted(values)
    return {"p50": round(statistics.median(v), 1), "p95": round(v[int(0.95 * (len(v) - 1))], 1)}


def configs(scored, llm_runs, t):
    """name -> (predictions, latencies)."""
    clf = [to_score(s["clf_prob"], t) for s in scored]
    out = {
        "heuristic": ([s["heuristic"] >= BLOCK_SCORE for s in scored], None),
        "classifier": ([c >= BLOCK_SCORE for c in clf], [s["clf_ms"] for s in scored]),
        "classifier+heuristic": ([combine(c, s["heuristic"]) >= BLOCK_SCORE for c, s in zip(clf, scored)], None),
    }
    for name, llm in llm_runs.items():
        out[f"llm {name}"] = ([r["llm"] >= BLOCK_SCORE for r in llm], [r["llm_ms"] for r in llm])
        # Production path (injection.analyse): a classifier or heuristic hit skips the LLM;
        # otherwise the score is max(classifier, heuristic, LLM).
        local = [combine(c, s["heuristic"]) for c, s in zip(clf, scored)]
        out[f"classifier+heuristic+llm {name}"] = (
            [max(l, r["llm"]) >= BLOCK_SCORE for l, r in zip(local, llm)],
            [s["clf_ms"] + (0 if l >= BLOCK_SCORE else r["llm_ms"]) for l, s, r in zip(local, scored, llm)])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--threshold", type=float)
    a = ap.parse_args()
    if a.split == "test" and a.threshold is None:
        sys.exit("Pass the threshold chosen on dev; the test split is never used for tuning.")
    rows = [json.loads(l) for l in (DATA / f"{a.split}.jsonl").read_text(encoding="utf-8").splitlines() if l]
    llm_runs = {}
    for m in MODELS:
        f = RESULTS / f"{a.split}-{m}.json"
        if f.exists():
            prev = json.loads(f.read_text())["rows"]
            assert [(r["label"], r["source"]) for r in prev] == [(r["label"], r["source"]) for r in rows], f
            llm_runs[m] = prev
    clf = InjectionClassifier()
    if not clf.available:
        sys.exit("Classifier not available: pip install -r requirements-classifier.txt and "
                 "python -m agentwall.layer3.classifier --download")
    scored = score_rows(rows, clf)
    thresholds = [a.threshold] if a.threshold is not None else [0.5, 0.9, 0.99, 0.999, 0.9999]
    y = [s["label"] for s in scored]
    reports = []
    for t in thresholds:
        rep = {"threshold": t, "configs": {}}
        for name, (pred, latency) in configs(scored, llm_runs, t).items():
            entry = {**metrics(y, pred)}
            if latency:
                entry["latency_ms"] = lat(latency)
            entry["by_source"] = {}
            for src, label in sorted({(s["source"], s["label"]) for s in scored}):
                idx = [i for i, s in enumerate(scored) if s["source"] == src and s["label"] == label]
                entry["by_source"][f"{src}/{'attack' if label else 'benign'}"] = round(
                    sum(pred[i] for i in idx) / len(idx), 3)
            rep["configs"][name] = entry
        reports.append(rep)
        print(f"t={t}")
        for name, e in rep["configs"].items():
            print(f"  {name:28s} P={e['precision']} R={e['recall']} F1={e['f1']} fp={e['fp']} fn={e['fn']} "
                  f"{e.get('latency_ms', '')}")
    out = RESULTS / f"classifier-{a.split}.json"
    out.write_text(json.dumps({"split": a.split, "reports": reports,
                               "rows": [{k: s[k] for k in ("label", "source", "clf_prob", "clf_ms", "heuristic")}
                                        for s in scored]}, indent=1))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
