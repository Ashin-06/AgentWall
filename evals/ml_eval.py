"""Evaluate the Layer 3 injection detector with a real model.

  python evals/ml_eval.py --build        # download public data, write frozen JSONL splits
  python evals/ml_eval.py --split dev    # pick the block threshold on dev only
  python evals/ml_eval.py --split test --threshold 0.8   # report on the held-out split

Needs a running Ollama with the model pulled (default llama3.2:3b). Results are written to
evals/results/<split>-<model>.json. See docs/EVALUATION.md.
"""
import argparse
import asyncio
import csv
import io
import json
import os
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DATA = ROOT / "evals" / "datasets" / "ml_eval"
RESULTS = ROOT / "evals" / "results"


# ---------------------------------------------------------------- dataset build
def _deepset(split):
    import httpx
    rows, offset = [], 0
    while True:
        for attempt in range(5):  # the rows API returns transient 502s
            r = httpx.get("https://datasets-server.huggingface.co/rows", timeout=60, params={
                "dataset": "deepset/prompt-injections", "config": "default",
                "split": split, "offset": offset, "length": 100})
            if r.status_code < 500:
                break
            time.sleep(2 * (attempt + 1))
        r.raise_for_status()
        batch = [x["row"] for x in r.json()["rows"]]
        rows += batch
        offset += len(batch)
        if len(batch) < 100:
            return [{"text": x["text"], "label": int(x["label"]), "source": f"deepset-{split}"} for x in rows]


def _jbb(kind, label):
    import httpx
    url = f"https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/{kind}-behaviors.csv"
    r = httpx.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    return [{"text": x["Goal"], "label": label, "source": f"jbb-{kind}"} for x in csv.DictReader(io.StringIO(r.text))]


def _fixtures(name, label):
    out = []
    for line in (ROOT / "evals" / "datasets" / f"{name}.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            c = json.loads(line)
            out.append({"tool_name": c["tool_name"], "arguments": c["arguments"], "label": label,
                        "source": f"agent-{name}"})
    return out


def build():
    rng = random.Random(0)
    train = _deepset("train")
    dev = (rng.sample([r for r in train if r["label"] == 1], 60)
           + rng.sample([r for r in train if r["label"] == 0], 60))
    test = (_deepset("test") + _jbb("harmful", 1) + _jbb("benign", 0)
            + _fixtures("malicious", 1) + _fixtures("benign", 0))
    DATA.mkdir(parents=True, exist_ok=True)
    for name, rows in (("dev", dev), ("test", test)):
        with open(DATA / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=True) + "\n")
        print(f"{name}: {len(rows)} rows, {sum(r['label'] for r in rows)} attacks")


# ---------------------------------------------------------------- evaluation
def to_call(row):
    from agentwall.layer1.normaliser import TextNormaliser
    call = {"session_id": "eval", "agent_id": "eval", "context": "",
            "tool_name": row.get("tool_name", "process_text"),
            "arguments": row.get("arguments", {"text": row.get("text", "")})}
    return TextNormaliser().normalise_call(call)  # same pre-processing as the proxy


def metrics(labels, preds):
    tp = sum(1 for y, p in zip(labels, preds) if y and p)
    fp = sum(1 for y, p in zip(labels, preds) if not y and p)
    fn = sum(1 for y, p in zip(labels, preds) if y and not p)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn, "n": len(labels)}


async def score_all(rows, model):
    os.environ["OLLAMA_MODEL"] = model
    from agentwall.layer3.injection import LLMInjectionClassifier
    from agentwall.layer3._heuristics import heuristic_score
    from agentwall.layer1.normaliser import normalise_text
    from agentwall.layer1.policy_engine import PolicyEngine
    clf, policy = LLMInjectionClassifier(), PolicyEngine()
    out = []
    for i, row in enumerate(rows):
        call = to_call(row)
        text = clf._collect_text(call)
        t0 = time.perf_counter()
        res = await clf._llm_classify(text, "", f"{call['tool_name']}({call['arguments']})")
        ms = (time.perf_counter() - t0) * 1000
        h, _ = heuristic_score(normalise_text(text))
        out.append({"label": row["label"], "source": row["source"], "llm": res.get("score", 0.0),
                    "llm_error": res.get("error"), "llm_ms": ms, "heuristic": h,
                    "policy_block": policy.check(call)["action"] == "BLOCK"})
        if (i + 1) % 25 == 0:
            print(f"  {i + 1}/{len(rows)}", flush=True)
    return out


def report(scored, threshold):
    ok = [s for s in scored if not s["llm_error"]]
    y = [s["label"] for s in ok]
    lat = sorted(s["llm_ms"] for s in ok)
    rep = {
        "threshold": threshold, "rows": len(scored), "llm_errors": len(scored) - len(ok),
        "llm": metrics(y, [s["llm"] >= threshold for s in ok]),
        "heuristic": metrics(y, [s["heuristic"] >= threshold for s in ok]),
        "policy_or_llm": metrics(y, [s["policy_block"] or s["llm"] >= threshold for s in ok]),
        "latency_ms": {"p50": round(statistics.median(lat), 1),
                       "p95": round(lat[int(0.95 * (len(lat) - 1))], 1)} if lat else {},
        "by_source": {},
    }
    for src, label in sorted({(s["source"], s["label"]) for s in ok}):
        sub = [s for s in ok if s["source"] == src and s["label"] == label]
        rate = lambda key: round(sum(1 for s in sub if (s["policy_block"] if key == "policy" else s[key] >= threshold)) / len(sub), 3)
        rep["by_source"][f"{src}/{'attack' if label else 'benign'}"] = {"n": len(sub), "flag_rate_llm": rate("llm"),
                                 "flag_rate_heuristic": rate("heuristic"), "flag_rate_policy": rate("policy")}
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--model", default="llama3.2:3b")
    ap.add_argument("--threshold", type=float, help="block threshold; on dev, omitted = sweep")
    a = ap.parse_args()
    if a.build:
        return build()
    rows = [json.loads(l) for l in (DATA / f"{a.split}.jsonl").read_text(encoding="utf-8").splitlines() if l]
    scored = asyncio.run(score_all(rows, a.model))
    if a.split == "test" and a.threshold is None:
        sys.exit("Pass the threshold chosen on dev; the test split is never used for tuning.")
    thresholds = [a.threshold] if a.threshold is not None else [0.5, 0.6, 0.7, 0.8, 0.9]
    reports = [report(scored, t) for t in thresholds]
    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / f"{a.split}-{a.model.replace(':', '_')}.json"
    out.write_text(json.dumps({"model": a.model, "split": a.split, "reports": reports, "rows": scored}, indent=1))
    for r in reports:
        print(f"t={r['threshold']} llm={r['llm']} heuristic={r['heuristic']} policy_or_llm={r['policy_or_llm']} "
              f"latency={r['latency_ms']} errors={r['llm_errors']}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
