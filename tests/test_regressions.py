from unittest.mock import Mock

import pytest

from agentwall.audit.write_queue import DBWriteQueue
from agentwall.metrics import MetricsRegistry


def test_latency_percentiles_use_milliseconds():
    metrics = MetricsRegistry()
    for value in range(1, 101):
        metrics.record_call("PERMIT", "read", "test", value)
    result = metrics.performance(queue_size=7)
    assert result["latency"] == {"p50": 50, "p95": 95, "p99": 99}
    assert result["sample_count"] == 100
    assert result["queue_size"] == 7


def test_empty_latency_has_no_invented_values():
    assert MetricsRegistry().performance()["latency"] == {"p50": 0, "p95": 0, "p99": 0}


def test_failed_write_preserves_chain_head():
    queue = DBWriteQueue.__new__(DBWriteQueue)
    queue._prev_hash = "previous-committed-hash"
    queue._con = Mock()
    queue._con.execute.side_effect = RuntimeError("write failed")
    row = ("session", "agent", "call", "read", {}, "PERMIT", "ok", {}, "", "test", 1, False, "test")
    with pytest.raises(RuntimeError):
        queue._sync_write(row)
    assert queue._prev_hash == "previous-committed-hash"
    queue._con.execute.side_effect = None
    assert queue._sync_write(row)
    assert queue._prev_hash != "previous-committed-hash"


def test_database_lock_never_terminates_processes(monkeypatch):
    connect = Mock(side_effect=RuntimeError("database is locked"))
    run = Mock()
    monkeypatch.setattr("agentwall.audit.write_queue.duckdb.connect", connect)
    monkeypatch.setattr("agentwall.audit.write_queue.time.sleep", lambda _: None)
    monkeypatch.setattr("subprocess.run", run)
    with pytest.raises(RuntimeError, match="database is locked"):
        DBWriteQueue()
    assert connect.call_count == 15
    run.assert_not_called()


def test_performance_endpoint(client):
    response = client.get("/api/performance")
    assert response.status_code == 200
    assert set(response.json()["latency"]) == {"p50", "p95", "p99"}


@pytest.mark.parametrize("endpoint", ["sessions", "violations"])
@pytest.mark.parametrize("limit", [-1, 0, 1001])
def test_list_limits_are_bounded(client, endpoint, limit):
    assert client.get(f"/api/{endpoint}?limit={limit}").status_code == 422


def test_performance_requires_auth(client, monkeypatch):
    monkeypatch.setattr("agentwall.auth.AUTH_ENABLED", True)
    assert client.get("/api/performance").status_code == 401
