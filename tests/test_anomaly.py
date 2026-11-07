"""The anomaly layer has to work on a default install, with no Redis."""
import time

from agentwall.layer2 import anomaly
from agentwall.layer2.anomaly import TemporalAnomalyDetector


def call(i, tool=None, path=None):
    return {"agent_id": "../agent under test", "tool_name": tool or f"tool_{i % 4}", "session_id": "s1",
            "timestamp": time.time() + i, "arguments": {"path": path or f"/tmp/{i % 4}"}}


def test_scores_after_enough_history_without_redis(tmp_path, monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setattr(anomaly, "MODEL_DIR", tmp_path)
    detector = TemporalAnomalyDetector()
    assert detector._r is None
    detector._models.clear()
    for i in range(90):
        result = detector.score(call(i))
    assert result["status"] == "scored"
    assert 0.0 <= result["anomaly_score"] <= 1.0
    assert [f.name for f in tmp_path.iterdir()] == [".._agent_under_test_ensemble.joblib"]  # stayed in the folder
