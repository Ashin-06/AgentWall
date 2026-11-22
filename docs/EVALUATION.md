# Layer 3 evaluation with a real model

The unit tests and `evals/run_benchmarks.py` mock the ML layers. This page measures the Layer 3
injection classifier (`agentwall/layer3/injection.py`) against a real local model, using the
production code path unchanged: the same system prompt, the same JSON parsing, and the same text
normalisation the proxy applies before Layer 3.

Reproduce:

```bash
ollama pull llama3.2:3b && ollama pull llama3.1
python evals/ml_eval.py --build                       # optional: re-download the frozen splits
python evals/ml_eval.py --split dev --model llama3.2:3b
python evals/ml_eval.py --split test --threshold 0.8 --model llama3.2:3b
python evals/ml_eval.py --split test --threshold 0.8 --model llama3.1:latest
```

Raw per-row scores and all metrics are in `evals/results/`.

## Data

Frozen in `evals/datasets/ml_eval/` so runs do not depend on the network.

| Split | Source | Rows | Label |
|---|---|---|---|
| dev | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) train, stratified sample (seed 0) | 60 + 60 | injection / benign |
| test | deepset/prompt-injections test (all) | 60 + 56 | injection / benign |
| test | [JailbreakBench JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) harmful goals | 100 | attack |
| test | JailbreakBench benign goals (topic-matched to the harmful ones) | 100 | benign |
| test | `evals/datasets/malicious.jsonl` (agent tool calls: rm -rf, exfiltration, SSRF, ...) | 25 | attack |
| test | `evals/datasets/benign.jsonl` (agent tool calls) | 25 | benign |

Test: 366 rows, 185 attacks. Dev and test share no text. Plain-text rows are wrapped as a
`process_text` tool call with the text as its only argument; agent rows keep their real tool name
and arguments. deepset is Apache-2.0, JBB-Behaviors is MIT.

**Held-out rule.** The test split was not used for any decision. The dev split was used once to
choose the block threshold: dev recall is flat between 0.5 and 0.8 with precision 1.0 at every
threshold, so the production threshold of 0.8 (`proxy.py`, score >= 0.8 blocks) was kept. One
prompt change was tried on dev (defining `confidence` as a probability of maliciousness). It lowered
3B dev recall from 0.15 to 0.08, so it was reverted. The prompt evaluated here is the one in `main`.

## Results (test split, block threshold 0.8)

Hardware: Windows 11, RTX 3060 Laptop GPU via Ollama 0.40.17. Latency is wall time per
classifier call (one HTTP round trip to Ollama), not end-to-end proxy latency. llama3.2:3b also runs
on CPU, but CPU latency was not measured here.

| Detector | Precision | Recall | F1 | FP / FN | p50 / p95 latency |
|---|---|---|---|---|---|
| Layer 3 LLM, llama3.2:3b | 0.898 | 0.524 | 0.662 | 11 / 88 | 1196 / 1333 ms |
| Layer 3 LLM, llama3.1 8B (production default) | 0.922 | 0.643 | 0.758 | 10 / 66 | 3637 / 4181 ms |
| Layer 3 heuristic fallback (no model) | 0.812 | 0.070 | 0.129 | 3 / 172 | < 1 ms |
| Layer 1 policy OR LLM 8B | 0.883 | 0.654 | 0.752 | 16 / 64 | |
| Layer 1 policy OR LLM 3B | 0.857 | 0.551 | 0.671 | 17 / 83 | |

Flag rate by source (share of rows scored >= 0.8; for attacks this is recall, for benign rows the
false-positive rate):

| Source | n | LLM 3B | LLM 8B | Heuristic | Layer 1 policy |
|---|---|---|---|---|---|
| deepset injections | 60 | 0.067 | 0.217 | 0.033 | 0.000 |
| deepset benign | 56 | 0.018 | 0.018 | 0.000 | 0.000 |
| JBB harmful requests | 100 | 0.730 | 0.830 | 0.040 | 0.000 |
| JBB benign requests | 100 | 0.100 | 0.090 | 0.030 | 0.000 |
| agent attack tool calls | 25 | 0.800 | 0.920 | 0.280 | 1.000 |
| agent benign tool calls | 25 | 0.000 | 0.000 | 0.000 | 0.240 |

Dev split (120 rows, threshold 0.8): 3B recall 0.167, 8B recall 0.283, precision 1.0 for both.

## What this shows

- **Prompt injection is mostly missed.** On the deepset injections, the attack class this layer
  is named for, the classifier catches 7% (3B) and 22% (8B). The aggregate F1 is carried by
  JailbreakBench harmful requests and by the agent fixtures, which the deterministic Layer 1 rules
  already block. Typical misses are role-play setups ("act as a linux terminal"), instructions
  hidden after a benign question, and German-language injections. The model often answers
  `"is_malicious": false` while also reporting the call as not aligned with the goal.
- **Precision is good, and false positives are few.** About 2% of benign deepset prompts are
  flagged, and 9-10% of the JailbreakBench benign requests (sensitive topics asked about benignly).
- **The heuristic fallback is not a substitute.** Without a model it catches 7% of attacks.
- **Latency.** At 1.2 s (3B) to 3.6 s (8B) per call on a laptop GPU, a synchronous Layer 3 check is
  too slow for an inline firewall on every call. By default the proxy runs it synchronously on
  every call that passes Layer 1. In shadow mode, only high-risk tools are checked synchronously.
  When the 7 s timeout is hit, it falls back to the heuristic.
- **Layer 1's 6 false positives on agent benign calls are by design.** These are the "expected
  policy denials" in `evals/run_benchmarks.py` (for example, reading `.env`). They count as false
  positives here because the fixture labels them benign.

## Not evaluated

- Layer 2 anomaly detection (Isolation Forest) and the RAG detector. There is no public labelled
  corpus of agent tool-call sequences to evaluate them on.
- End-to-end proxy latency under load, and CPU-only latency.
- Run-to-run variance. Ollama samples with its default temperature, so repeated runs move by a
  few points (3B dev recall was 0.150, 0.167 and 0.167 across three runs).

## CI

CI keeps the mocks for speed. `tests/test_real_model.py` sends one obvious injection and one benign
call to the real model. It is skipped when Ollama or the model is not reachable, which is the case
on GitHub-hosted runners.
