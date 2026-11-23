"""Every Redis key the detectors write gets a TTL; the anomaly session hash keeps start_ts."""
import time
from unittest.mock import MagicMock

from agentwall.layer2.anomaly import TemporalAnomalyDetector
from agentwall.layer2.trust_graph import TrustGraph
from agentwall.layer4.campaign import CampaignDetector


def _expired_keys(r):
    return {c.args[0] for c in r.expire.call_args_list} | {
        c.args[0] for c in r.set.call_args_list if c.kwargs.get("ex")}


def test_trust_graph_chain_keys_expire():
    tg = TrustGraph.__new__(TrustGraph)
    tg.redis_url, tg._r = "redis://x", MagicMock()
    tg._r.smembers.return_value = {"orchestrator"}  # a1 joins an existing chain
    tg.check_delegation({"session_id": "s1", "agent_id": "a1", "tool_name": "search", "arguments": {}})
    assert "chain:s1" in _expired_keys(tg._r)


def test_trust_graph_has_no_implicit_redis_default(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert TrustGraph().redis_url is None


def test_anomaly_vocab_expires_and_session_keeps_start_ts():
    det = TemporalAnomalyDetector.__new__(TemporalAnomalyDetector)
    det._r = MagicMock()
    det._r.hgetall.return_value = {}
    det._r.hlen.return_value = 0
    det._r.lrange.return_value = []
    det._featurise({"agent_id": "a1", "tool_name": "search", "session_id": "s1",
                    "arguments": {}, "timestamp": time.time()})
    assert "anomaly:vocab:a1" in _expired_keys(det._r)
    mapping = next(c.kwargs["mapping"] for c in det._r.hset.call_args_list if "mapping" in c.kwargs)
    assert "start_ts" in mapping


def test_campaign_attempt_stream_expires():
    cd = CampaignDetector.__new__(CampaignDetector)
    cd._r = MagicMock()
    cd._r.keys.return_value = []
    cd._r.zrangebyscore.return_value = []
    cd._cluster_redis({"event_id": "e", "session_id": "s", "agent_id": "a", "fp": 1,
                       "ts": time.time(), "verdict": "BLOCK", "text": "x"})
    assert "attempts_stream" in _expired_keys(cd._r)
