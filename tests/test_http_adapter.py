"""Tests for the HTTP adapter, using an injected fake transport."""

from __future__ import annotations

from typing import Any

from gauntlet.target.http_adapter import HTTPAdapter


def test_maps_response_to_target_result() -> None:
    captured: dict[str, Any] = {}

    def fake_transport(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        captured["endpoint"] = endpoint
        captured["payload"] = payload
        return {
            "output_text": "hello from langgraph",
            "tool_calls": [
                {"id": "t1", "name": "search", "arguments": {"q": "balance"}},
            ],
            "system_prompt": "You are a helpful agent.",
        }

    adapter = HTTPAdapter("http://localhost:8123/run", transport=fake_transport)
    result = adapter.send("what is my balance?")

    assert captured["endpoint"] == "http://localhost:8123/run"
    assert captured["payload"]["user_text"] == "what is my balance?"
    assert captured["payload"]["session_id"].startswith("http-")
    assert result.output_text == "hello from langgraph"
    assert result.system_prompt == "You are a helpful agent."
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "search"
    assert result.tool_calls[0].arguments == {"q": "balance"}


def test_handles_minimal_response() -> None:
    def fake_transport(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {"output_text": "ok"}

    adapter = HTTPAdapter("http://localhost/run", transport=fake_transport)
    result = adapter.send("hi")
    assert result.output_text == "ok"
    assert result.tool_calls == []
    assert result.system_prompt is None


def test_reset_rotates_session_id() -> None:
    seen: list[str] = []

    def fake_transport(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        seen.append(payload["session_id"])
        return {"output_text": "ok"}

    adapter = HTTPAdapter("http://localhost/run", transport=fake_transport)
    adapter.send("one")
    first = seen[-1]
    adapter.reset()
    adapter.send("two")
    second = seen[-1]
    assert first != second
