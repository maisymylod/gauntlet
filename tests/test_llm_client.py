"""Tests for the stub client and request fingerprinting."""

from __future__ import annotations

import pytest

from gauntlet.llm.client import StubLLMClient, StubMiss, fingerprint
from gauntlet.llm.types import LLMRequest, LLMResponse, ToolCall, ToolDef


def _request(text: str = "hello") -> LLMRequest:
    return LLMRequest(model="m", messages=[{"role": "user", "content": text}])


def test_stub_serves_queue_in_order() -> None:
    client = StubLLMClient(
        responses=[
            LLMResponse.make(stop_reason="end_turn", text="first"),
            LLMResponse.make(stop_reason="end_turn", text="second"),
        ]
    )
    assert client.complete(_request()).text == "first"
    assert client.complete(_request()).text == "second"
    assert len(client.calls) == 2


def test_stub_serves_by_fingerprint() -> None:
    req = _request("keyed")
    resp = LLMResponse.make(stop_reason="end_turn", text="matched")
    client = StubLLMClient(by_fingerprint={fingerprint(req): resp})
    assert client.complete(req).text == "matched"


def test_stub_miss_raises() -> None:
    client = StubLLMClient()
    with pytest.raises(StubMiss):
        client.complete(_request())


def test_fingerprint_is_stable_and_sensitive() -> None:
    a = _request("same")
    b = _request("same")
    c = _request("different")
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(c)


def test_fingerprint_tracks_tools() -> None:
    plain = _request()
    with_tool = LLMRequest(
        model="m",
        messages=[{"role": "user", "content": "hello"}],
        tools=(ToolDef(name="t", description="d", input_schema={"type": "object"}),),
    )
    assert fingerprint(plain) != fingerprint(with_tool)


def test_response_make_builds_tool_use_blocks() -> None:
    call = ToolCall(id="tc1", name="read_file", arguments={"path": "/x"})
    resp = LLMResponse.make(stop_reason="tool_use", text="thinking", tool_calls=(call,))
    blocks = resp.assistant_message()["content"]
    assert blocks[0] == {"type": "text", "text": "thinking"}
    assert blocks[1]["type"] == "tool_use"
    assert blocks[1]["name"] == "read_file"
    assert blocks[1]["input"] == {"path": "/x"}
