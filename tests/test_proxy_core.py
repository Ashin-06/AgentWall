"""Proxy wiring: circuit breaker on model errors, injection score reaching campaign correlation."""
import asyncio
from unittest.mock import AsyncMock

from agentwall.proxy import AgentWallProxy


def _proxy(analyse_result):
    proxy = AgentWallProxy(audit_logger=AsyncMock())
    proxy._campaign = AsyncMock()
    proxy._campaign.ingest.return_value = None
    proxy.injection.analyse = AsyncMock(return_value=analyse_result)
    return proxy


def _call(i=0):
    return {"session_id": f"core_{i}", "agent_id": "vscode_copilot", "tool_name": "search",
            "arguments": {"q": "weather in paris"}}


def test_model_error_result_trips_breaker_and_skips_model():
    proxy = _proxy({"score": 0.0, "error": "connection refused", "source": "llm_error_fallback"})
    asyncio.run(proxy.evaluate(_call(1)))
    assert proxy.breaker_open
    res = asyncio.run(proxy._run_semantic_guard(_call(2)))
    assert res["source"] == "heuristic_breaker_open"
    assert proxy.injection.analyse.await_count == 1  # second call did not reach the model


def test_breaker_closes_after_success_in_half_open_state():
    proxy = _proxy({"score": 0.0, "source": "llm_ollama"})
    proxy._record_semantic_failure()
    proxy._injection_failed_at -= 31  # cool-down elapsed
    asyncio.run(proxy._run_semantic_guard(_call(3)))
    assert proxy._injection_failure_rate == 0.0 and not proxy.breaker_open


def test_audit_path_passes_injection_score_to_campaign():
    proxy = _proxy({"score": 0.5, "source": "llm_ollama", "reasoning": "suspicious"})
    event = asyncio.run(proxy.evaluate(_call(4)))
    assert event["verdict"] == "AUDIT"
    inj = proxy._campaign.ingest.await_args.args[2]
    assert inj["score"] == 0.5
