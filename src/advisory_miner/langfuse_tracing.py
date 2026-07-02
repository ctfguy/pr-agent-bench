from __future__ import annotations

from contextvars import ContextVar
from contextlib import contextmanager, nullcontext
import os
from typing import Any, Iterator


_CURRENT_SPAN: ContextVar[Any | None] = ContextVar("advisory_miner_langfuse_span", default=None)


class LangfuseTracer:
    def __init__(self, enabled: bool = True, session_id: str | None = None):
        self.enabled = enabled
        self.session_id = _clean_session_id(session_id or os.environ.get("LANGFUSE_SESSION_ID"))
        self.client = None
        if not enabled:
            return
        public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
        secret_key = os.environ.get("LANGFUSE_SECRET_KEY")
        base_url = os.environ.get("LANGFUSE_BASE_URL") or os.environ.get("LANGFUSE_HOST")
        if not public_key or not secret_key:
            return
        if base_url and not os.environ.get("LANGFUSE_BASE_URL"):
            os.environ["LANGFUSE_BASE_URL"] = base_url
        try:
            from langfuse import get_client

            self.client = get_client()
        except Exception:
            self.client = None

    @property
    def available(self) -> bool:
        return self.client is not None

    def generation(
        self,
        name: str,
        model: str,
        prompt: Any,
        response: Any,
        usage: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self.trace_generation(name, model, prompt, metadata=metadata) as generation:
            if generation is None:
                return
            generation.update(
                output=response,
                usage_details=_usage_details(usage or {}),
                cost_details=_cost_details(model, usage or {}),
                metadata=metadata or {},
            )

    @contextmanager
    def trace_generation(
        self,
        name: str,
        model: str,
        prompt: Any,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[Any | None]:
        if self.client is None:
            yield None
            return
        try:
            manager = self.client.start_as_current_observation(
                as_type="generation",
                name=name,
                model=model,
                input=prompt,
                metadata=metadata or {},
            )
        except Exception:
            yield None
            return
        with manager as generation:
            yield generation

    @contextmanager
    def trace_tool(
        self,
        name: str,
        input: Any,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[Any | None]:
        if self.client is None:
            yield None
            return
        try:
            manager = self.client.start_as_current_observation(
                as_type="tool",
                name=name,
                input=input,
                metadata=metadata or {},
            )
        except Exception:
            yield None
            return
        with manager as tool:
            yield tool

    @contextmanager
    def span(
        self,
        name: str,
        input: Any | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> Iterator[Any | None]:
        if self.client is None:
            yield None
            return
        try:
            from langfuse import propagate_attributes

            manager = self.client.start_as_current_observation(
                as_type="span",
                name=name,
                input=input,
                metadata=metadata or {},
            )
            attributes = propagate_attributes(
                trace_name=name,
                session_id=self.session_id,
                metadata=_propagated_metadata(metadata or {}),
                tags=tags or [],
            )
        except Exception:
            manager = nullcontext(None)
            attributes = nullcontext()
        with manager as span:
            token = _CURRENT_SPAN.set(span)
            try:
                with attributes:
                    yield span
            finally:
                _CURRENT_SPAN.reset(token)

    def flush(self) -> None:
        if self.client is None:
            return
        flush = getattr(self.client, "flush", None)
        if callable(flush):
            flush()

    def score(self, name: str, value: float, metadata: dict[str, Any] | None = None) -> None:
        if self.client is None:
            return
        kwargs = {"name": name, "value": value, "data_type": "NUMERIC", "metadata": metadata or {}}
        current_span = _CURRENT_SPAN.get()
        score_trace = getattr(current_span, "score_trace", None)
        if callable(score_trace):
            try:
                score_trace(**kwargs)
                return
            except Exception:
                return
        create_score = getattr(self.client, "score_current_trace", None)
        if not callable(create_score):
            create_score = getattr(self.client, "create_score", None)
            kwargs = {
                "name": name,
                "value": value,
                "session_id": self.session_id,
                "data_type": "NUMERIC",
                "metadata": metadata or {},
            }
        if not callable(create_score):
            return
        try:
            create_score(**kwargs)
        except Exception:
            return


def build_langfuse_tracer(session_id: str | None = None) -> LangfuseTracer | None:
    tracer = LangfuseTracer(enabled=True, session_id=session_id)
    return tracer


def _usage_details(usage: dict[str, Any]) -> dict[str, int]:
    input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
    total_tokens = int(usage.get("total_tokens", input_tokens + output_tokens) or 0)
    details = {"input": input_tokens, "output": output_tokens}
    if total_tokens:
        details["total"] = total_tokens
    return details


def _cost_details(model: str, usage: dict[str, Any]) -> dict[str, float]:
    input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
    if input_tokens <= 0 and output_tokens <= 0:
        return {}
    lowered = model.lower()
    if "nano" in lowered:
        in_per_m, out_per_m = 0.05, 0.40
    elif "mini" in lowered:
        in_per_m, out_per_m = 0.25, 2.00
    else:
        in_per_m, out_per_m = 1.25, 10.00
    input_cost = input_tokens * in_per_m / 1_000_000
    output_cost = output_tokens * out_per_m / 1_000_000
    return {"input": input_cost, "output": output_cost, "total": input_cost + output_cost}


def _propagated_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): str(value)[:200]
        for key, value in metadata.items()
        if str(key).replace("_", "").isalnum() and value is not None
    }


def _clean_session_id(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = "".join(ch for ch in value if ord(ch) < 128).strip()
    return cleaned[:199] or None
