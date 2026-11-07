"""The anomaly layer has to work on a default install, with no Redis."""
import time

from agentwall.layer2.anomaly import TemporalAnomalyDetector


def test_scores_after_enough_history_without_redis(tmp_path, monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.chdir(tmp_path)
    detector = TemporalAnomalyDetector()
    assert detector._r is None
    detector._models.clear()
    result = {}
    for i in range(90):
        call = {"agent_id": "agent-under-test", "tool_name": f"tool_{i % 4}", "session_id": "s1",
                "timestamp": time.time() + i, "arguments": {"path": f"/tmp/{i}"}}
        result = detector.score(call)
    assert result["status"] == "scored"
    assert 0.0 <= result["anomaly_score"] <= 1.0
