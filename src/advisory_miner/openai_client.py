from __future__ import annotations

from contextlib import nullcontext
import json
import random
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .runtime import ResponseCache, current_cost_cap, current_metrics


class OpenAIClientError(RuntimeError):
    pass


class OpenAIClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        timeout: int = 90,
        cache: ResponseCache | None = None,
        tracer: Any | None = None,
    ):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.openai.com/v1/responses"
        self.cache = cache
        self.tracer = tracer

    def json_response(self, system: str, user: dict[str, Any] | str, max_output_tokens: int = 1800) -> dict[str, Any]:
        user_text = user if isinstance(user, str) else json.dumps(user, separators=(",", ":"))
        cache_key = None
        if self.cache is not None:
            cache_key = ResponseCache.key("openai_json", self.model, system, user_text, max_output_tokens)
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        body = {
            "model": self.model,
            "input": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
            "max_output_tokens": max_output_tokens,
        }
        if _supports_reasoning_effort(self.model):
            body["reasoning"] = {"effort": "minimal"}
        payload = self._post_traced("openai-json", body)
        self._accumulate_usage({"input_tokens": 0, "output_tokens": 0}, payload)
        text = self._extract_text(payload)
        if not text:
            raise OpenAIClientError("OpenAI response did not contain output text")
        parsed = parse_json_object(text)
        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, parsed)
        return parsed

    def tool_loop(
        self,
        system: str,
        user_payload: Any,
        tools: list[dict[str, Any]],
        handlers: dict[str, Callable[[dict[str, Any]], Any]],
        max_turns: int = 10,
        max_output_tokens: int = 4000,
        tool_output_char_limit: int = 30000,
    ) -> dict[str, Any]:
        """Run an OpenAI Responses tool-calling loop until the model returns no
        further function calls or `max_turns` is exhausted.

        - `handlers` maps tool name to a callable that takes the parsed
          arguments dict and returns either a dict (serialized as JSON for the
          model) or a string.
        - Any call to a tool named ``finalize_finding`` is intercepted and its
          arguments are recorded into the returned ``finalized`` map under the
          ``target`` key. The handler is still invoked if registered, so the
          investigator can run validation work.
        - Returns a dict with ``finalized``, ``tool_calls``, ``final_text``,
          ``usage``, and ``turns``.
        """
        user_text = (
            user_payload
            if isinstance(user_payload, str)
            else json.dumps(user_payload, separators=(",", ":"))
        )
        input_items: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_text},
        ]
        tool_calls_trace: list[dict[str, Any]] = []
        finalized: dict[str, dict[str, Any]] = {}
        finish_text: str | None = None
        usage = {"input_tokens": 0, "output_tokens": 0}
        completed_turns = 0

        for turn in range(max_turns):
            completed_turns = turn + 1
            body: dict[str, Any] = {
                "model": self.model,
                "input": input_items,
                "tools": tools,
                "parallel_tool_calls": True,
                "max_output_tokens": max_output_tokens,
            }
            if _supports_reasoning_effort(self.model):
                body["reasoning"] = {"effort": "minimal"}
            response = self._post_traced("openai-tool-loop", body)
            self._accumulate_usage(usage, response)

            function_calls: list[dict[str, Any]] = []
            text_chunks: list[str] = []
            for item in response.get("output") or []:
                kind = item.get("type")
                if kind == "function_call":
                    function_calls.append(item)
                else:
                    for content in item.get("content") or []:
                        if content.get("type") in {"output_text", "text"} and content.get("text"):
                            text_chunks.append(content["text"])

            if not function_calls:
                finish_text = "\n".join(text_chunks).strip() or None
                break

            for fc in function_calls:
                name = fc.get("name", "")
                arguments_raw = fc.get("arguments") or "{}"
                try:
                    arguments = json.loads(arguments_raw)
                except json.JSONDecodeError:
                    arguments = {}
                tool_calls_trace.append({"name": name, "arguments": arguments})

                trace_tool = getattr(self.tracer, "trace_tool", None) if self.tracer is not None else None
                tool_context = (
                    trace_tool(
                        name or "unknown_tool",
                        _trace_value(arguments),
                        metadata={
                            "turn": turn + 1,
                            "callid": fc.get("call_id") or "",
                            "toolname": name,
                        },
                    )
                    if callable(trace_tool)
                    else nullcontext(None)
                )
                with tool_context as tool_observation:
                    if name == "finalize_finding":
                        target = arguments.get("target")
                        if target:
                            finalized[target] = arguments
                        output_payload: Any = {"ok": True, "target": target}
                    elif name in handlers:
                        try:
                            raw_output = handlers[name](arguments)
                            output_payload = (
                                raw_output
                                if isinstance(raw_output, (dict, list))
                                else {"result": raw_output}
                            )
                        except Exception as exc:
                            output_payload = {"error": str(exc)}
                    else:
                        output_payload = {"error": f"unknown tool {name}"}
                    if tool_observation is not None:
                        update = {
                            "output": _trace_value(output_payload),
                            "metadata": {"toolname": name, "turn": turn + 1},
                        }
                        if isinstance(output_payload, dict) and output_payload.get("error"):
                            update["level"] = "ERROR"
                            update["status_message"] = str(output_payload["error"])
                        tool_observation.update(**update)

                input_items.append(fc)
                serialized = json.dumps(output_payload, default=str)
                if len(serialized) > tool_output_char_limit:
                    serialized = serialized[:tool_output_char_limit] + '..."(truncated)"'
                input_items.append(
                    {
                        "type": "function_call_output",
                        "call_id": fc.get("call_id"),
                        "output": serialized,
                    }
                )

        return {
            "finalized": finalized,
            "tool_calls": tool_calls_trace,
            "final_text": finish_text,
            "usage": usage,
            "turns": completed_turns,
        }

    def _post(self, body: dict[str, Any], max_retries: int = 3) -> dict[str, Any]:
        cap = current_cost_cap()
        if cap is not None and current_metrics().estimated_openai_cost_usd >= cap:
            raise OpenAIClientError(f"per-advisory OpenAI cost cap exceeded: ${cap:.4f}")
        encoded = json.dumps(body).encode("utf-8")
        for attempt in range(max_retries + 1):
            request = urllib.request.Request(
                self.url,
                data=encoded,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")
                # Retry on transient server-side and rate-limit errors.
                if exc.code in {429, 500, 502, 503, 504} and attempt < max_retries:
                    self._backoff(attempt)
                    continue
                raise OpenAIClientError(f"OpenAI request failed: {exc.code}: {detail[:500]}") from exc
            except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
                # Transient network errors: ECONNRESET, "Remote end closed connection",
                # DNS hiccups. Retry a few times before giving up.
                if attempt < max_retries:
                    self._backoff(attempt)
                    continue
                raise OpenAIClientError(f"OpenAI request failed: {exc}") from exc
        raise OpenAIClientError("OpenAI request failed after retries")

    def _post_traced(self, name: str, body: dict[str, Any]) -> dict[str, Any]:
        trace_generation = getattr(self.tracer, "trace_generation", None) if self.tracer is not None else None
        if not callable(trace_generation):
            return self._post(body)
        metadata = {
            "provider": "openai",
            "endpoint": "responses",
            "responseformat": "json" if name == "openai-json" else "toolloop",
            "toolcount": len(body.get("tools") or []),
        }
        model_parameters = {
            key: body[key]
            for key in ("max_output_tokens", "parallel_tool_calls")
            if key in body and isinstance(body[key], (str, int, float, bool))
        }
        prompt = {
            "input": body.get("input"),
            "tools": [tool.get("name") for tool in body.get("tools") or [] if isinstance(tool, dict)],
        }
        with trace_generation(name, self.model, prompt, metadata={**metadata, **model_parameters}) as generation:
            try:
                payload = self._post(body)
            except Exception as exc:
                if generation is not None:
                    generation.update(level="ERROR", status_message=str(exc))
                raise
            if generation is not None:
                usage = payload.get("usage") or {}
                generation.update(
                    output={"status": payload.get("status"), "output": payload.get("output")},
                    usage_details=_langfuse_usage_details(usage),
                    cost_details=_langfuse_cost_details(self.model, usage),
                    metadata={**metadata, "responseid": payload.get("id")},
                )
            return payload

    def _backoff(self, attempt: int) -> None:
        time.sleep(min(2 ** attempt + random.random(), 30.0))

    def _accumulate_usage(self, usage: dict[str, int], response: dict[str, Any]) -> None:
        info = response.get("usage") or {}
        in_tokens = int(info.get("input_tokens", 0) or 0)
        out_tokens = int(info.get("output_tokens", 0) or 0)
        usage["input_tokens"] += in_tokens
        usage["output_tokens"] += out_tokens
        metrics = current_metrics()
        metrics.openai_calls += 1
        metrics.openai_input_tokens += in_tokens
        metrics.openai_output_tokens += out_tokens
        metrics.estimated_openai_cost_usd += estimate_cost_usd(self.model, in_tokens, out_tokens)

    def _extract_text(self, payload: dict[str, Any]) -> str:
        texts: list[str] = []
        for item in payload.get("output") or []:
            for content in item.get("content") or []:
                if content.get("type") in {"output_text", "text"} and content.get("text"):
                    texts.append(content["text"])
        if texts:
            return "\n".join(texts)
        if payload.get("output_text"):
            return str(payload["output_text"])
        return ""

def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise OpenAIClientError("OpenAI response was not valid JSON")
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise OpenAIClientError("OpenAI response JSON must be an object")
    return parsed


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    # Conservative defaults; env-specific pricing can be modeled later without
    # changing callers. Values are per 1M tokens.
    lowered = model.lower()
    if "nano" in lowered:
        in_per_m, out_per_m = 0.05, 0.40
    elif "mini" in lowered:
        in_per_m, out_per_m = 0.25, 2.00
    else:
        in_per_m, out_per_m = 1.25, 10.00
    return (input_tokens / 1_000_000) * in_per_m + (output_tokens / 1_000_000) * out_per_m


def _langfuse_usage_details(usage: dict[str, Any]) -> dict[str, int]:
    input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
    total_tokens = int(usage.get("total_tokens", input_tokens + output_tokens) or 0)
    details = {"input": input_tokens, "output": output_tokens}
    if total_tokens:
        details["total"] = total_tokens
    return details


def _langfuse_cost_details(model: str, usage: dict[str, Any]) -> dict[str, float]:
    input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
    total = estimate_cost_usd(model, input_tokens, output_tokens)
    return {"total": total} if total > 0 else {}


def _trace_value(value: Any, max_chars: int = 12000) -> Any:
    try:
        encoded = json.dumps(value, default=str)
    except TypeError:
        encoded = str(value)
    if len(encoded) <= max_chars:
        return value
    return {"truncated": True, "chars": len(encoded), "preview": encoded[:max_chars]}


def _supports_reasoning_effort(model: str) -> bool:
    lowered = model.lower()
    return lowered.startswith(("gpt-5", "o1", "o3", "o4"))
