"""
Temporal Isolation Forest Ensemble with Redis State.
Ensures anomaly baselines are shared across pods.
"""
print("[Anomaly] Importing stdlib...")
import math
import time
import joblib
import os
import json
import redis
import mmh3
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

# Windows Fix: Use local models directory instead of root /data
MODEL_DIR = Path(os.getenv("AGENTWALL_MODEL_DIR", "models"))
print(f"[Anomaly] MODEL_DIR: {MODEL_DIR}")
MODEL_DIR.mkdir(parents=True, exist_ok=True)
print("[Anomaly] model directory ready.")

# Heavy imports moved inside class or conditional for faster dev startup
def get_iso_forest():
    print("[Anomaly] Importing heavy libraries (numpy/sklearn)...")
    import numpy as np
    from sklearn.ensemble import IsolationForest
    return np, IsolationForest

WINDOW_SIZES = [5, 15, 60]
HISTORY_SIZES = [500, 2000, None]

class TemporalAnomalyDetector:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.redis_url = os.getenv("REDIS_URL")
        self._r = None
        if self.redis_url:
            self._r = redis.from_url(self.redis_url, decode_responses=True)
            print(f"[AnomalyDetector] Connected to Redis for state sharing: {self.redis_url}")

        self._models: dict[str, list] = {}
        self._load_all()

    def _get_history(self, agent_id: str) -> list:
        if self._r:
            data = self._r.lrange(f"anomaly:history:{agent_id}", 0, -1)
            return [json.loads(d) for d in data]
        return []

    def _add_history(self, agent_id: str, entry: tuple):
        if self._r:
            self._r.lpush(f"anomaly:history:{agent_id}", json.dumps(entry))
            self._r.ltrim(f"anomaly:history:{agent_id}", 0, 4999)
            self._r.expire(f"anomaly:history:{agent_id}", 86400)

    def score(self, call: dict) -> dict:
        agent_id = call["agent_id"]
        features = self._featurise(call)
        self._add_history(agent_id, (features, call["tool_name"], call.get("timestamp", time.time())))

        # Auto-train logic (local cache check)
        history_len = self._r.llen(f"anomaly:history:{agent_id}") if self._r else 0
        if agent_id not in self._models and history_len >= 80:
            self._train(agent_id)

        if agent_id not in self._models:
            return {"anomaly_score": 0.0, "status": "collecting", "n_samples": history_len}

        models = self._models[agent_id]
        X = np.array([features])
        scores = []
        weights = [0.5, 0.3, 0.2]

        for model, w in zip(models, weights):
            if model is None: continue
            raw = model.score_samples(X)[0]
            normalised = max(0.0, min(1.0, -raw * 1.2))
            scores.append(normalised * w)

        final = sum(scores) / sum(w for m, w in zip(models, weights) if m is not None)
        return {"anomaly_score": round(float(final), 4), "status": "scored"}

    def _featurise(self, call: dict) -> list[float]:
        agent_id = call["agent_id"]
        tool_name = call["tool_name"]
        session_id = call["session_id"]
        ts = call.get("timestamp", time.time())
        args = call.get("arguments", {})

        # Distributed state from Redis
        if self._r:
            vocab = self._r.hgetall(f"anomaly:vocab:{agent_id}")
            if tool_name not in vocab:
                idx = self._r.hlen(f"anomaly:vocab:{agent_id}")
                self._r.hset(f"anomaly:vocab:{agent_id}", tool_name, idx)
                tool_idx = float(idx)
            else:
                tool_idx = float(vocab[tool_name])
            
            s_key = f"anomaly:session:{session_id}"
            state = self._r.hgetall(s_key)
            if not state:
                state = {"last_tool": "__START__", "call_count": "0", "start_ts": str(ts)}
            
            last_tool = state["last_tool"]
            last_idx = float(vocab.get(last_tool, -1))
            call_count = float(state["call_count"])
            session_age = ts - float(state["start_ts"])
            
            # Update session state in Redis
            self._r.hset(s_key, mapping={"last_tool": tool_name, "call_count": str(int(call_count) + 1)})
            self._r.expire(s_key, 3600)
            
            # Call rates from history stream
            history = self._get_history(agent_id)
            history_ts = [h[2] for h in history]
            rates = [float(sum(1 for t in history_ts if ts - t < w)) for w in WINDOW_SIZES]
        else:
            # Fallback for local
            tool_idx = 0.0; last_idx = -1.0; call_count = 0.0; session_age = 0.0; rates = [0,0,0]
            last_tool = "__START__"

        arg_str = str(args)
        arg_hash = float(mmh3.hash(arg_str, signed=False) % 10000) / 10000.0
        entropy = self._entropy(arg_str)

        return [tool_idx, time.gmtime(ts).tm_hour, time.gmtime(ts).tm_wday, 
                1.0 if time.gmtime(ts).tm_wday >= 5 else 0.0, 
                rates[0], rates[1], rates[2], float(len(arg_str)), arg_hash, 
                entropy, last_idx, call_count, session_age, 
                1.0 if last_tool == "__START__" else 0.0, ts % 86400]

    @staticmethod
    def _entropy(s: str) -> float:
        if not s: return 0.0
        from collections import Counter
        freq = Counter(s); n = len(s)
        return -sum((v/n) * math.log2(v/n) for v in freq.values())

    def _get_model(self, agent_id: str, window: int):
        key = f"{agent_id}:{window}"
        if key not in self._models:
            np, IsolationForest = get_iso_forest()
            self._models[key] = [
                IsolationForest(n_estimators=50, contamination=0.01),
                deque(maxlen=1000)
            ]
        return self._models[key]

    def _train(self, agent_id: str):
        history = self._get_history(agent_id)
        if len(history) < 20: return
        np, IsolationForest = get_iso_forest()
        X = np.array([h[0] for h in history])
        models = []
        for max_samples in HISTORY_SIZES:
            subset = X[-max_samples:] if max_samples else X
            if len(subset) < 20: models.append(None); continue
            m = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            m.fit(subset); models.append(m)
        self._models[agent_id] = models
        self._save(agent_id, models)

    def _save(self, agent_id: str, models):
        path = MODEL_DIR / f"{agent_id}_ensemble.joblib"
        joblib.dump(models, path)

    def _load_all(self):
        for path in MODEL_DIR.glob("*_ensemble.joblib"):
            agent_id = path.stem.replace("_ensemble", "")
            try: self._models[agent_id] = joblib.load(path)
            except: pass
