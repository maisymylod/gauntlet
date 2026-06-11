"""Drive an external agent (for example a LangGraph app) over a local HTTP endpoint.

This is the bridge from gauntlet to an existing agent stack. The endpoint is
expected to honor a small JSON contract:

    POST <endpoint>
    request:  {"session_id": str, "user_text": str}
    response: {"output_text": str,
               "tool_calls": [{"id": str, "name": str, "arguments": object}, ...],
               "system_prompt": str | null}

The transport is injectable so tests exercise the adapter offline with a fake.
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any

from gauntlet.llm.types import ToolCall

from .base import TargetResult

Transport = Callable[[str, dict[str, Any]], dict[str, Any]]


def urllib_transport(timeout: float = 30.0) -> Transport:
    """A transport backed by the standard library (no third-party deps)."""

    def _post(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 (local endpoint, operator-controlled)
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read().decode("utf-8")
        parsed: dict[str, Any] = json.loads(body)
        return parsed

    return _post


class HTTPAdapter:
    """A :class:`Target` that proxies turns to an HTTP endpoint."""

    name = "http-adapter"

    def __init__(
        self,
        endpoint: str,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.endpoint = endpoint
        self._transport: Transport = transport or urllib_transport()
        self._session_id = _new_session_id()

    def reset(self) -> None:
        self._session_id = _new_session_id()

    def send(self, user_text: str) -> TargetResult:
        payload = {"session_id": self._session_id, "user_text": user_text}
        response = self._transport(self.endpoint, payload)
        tool_calls = [
            ToolCall(
                id=str(call.get("id", "")),
                name=str(call.get("name", "")),
                arguments=dict(call.get("arguments", {})),
            )
            for call in response.get("tool_calls", [])
        ]
        return TargetResult(
            output_text=str(response.get("output_text", "")),
            tool_calls=tool_calls,
            system_prompt=response.get("system_prompt"),
            raw={"session_id": self._session_id, "response": response},
        )


def _new_session_id() -> str:
    return f"http-{uuid.uuid4().hex[:12]}"
