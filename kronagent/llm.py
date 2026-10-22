"""
LLM client for triage enrichment.

Thin async wrapper around the Google GenAI SDK with schema-constrained output
and exponential-backoff retry for free-tier / transient rate limits. The LLM
is used ONLY for reasoning about a detection GuardDuty has already made — it
never selects the concrete resource a containment action targets (those come
from the parsed finding), so a prompt-injection payload in telemetry cannot
redirect an action onto an attacker-chosen resource.

Two backends share one interface (`TriageLLM.structured`):

  * `GeminiTriageClient`  the Gemini API, keyed by GEMINI_API_KEY.
  * `BedrockTriageClient` Claude in Amazon Bedrock, signed with the ambient AWS
    credentials (an ECS task role in the in-account deployment), so a
    customer's findings never leave their own AWS account.

`build_triage_client()` picks one from KRONAGENT_LLM. Callers treat any error
from `structured()` as "no model verdict" and fail towards a person.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import os
import random
from typing import Awaitable, Callable, Optional, Protocol, TypeVar

from google import genai
from google.genai import errors, types
from pydantic import BaseModel

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

T = TypeVar("T", bound=BaseModel)

# gemini-3.1-flash-lite: GA, fast (~2s vs 34-85s for 3.5-flash with thinking on),
# cheap, and well-suited to triage (a bounded classification/reasoning task).
# Fast triage matters for a real-time pipeline. The free-tier daily quota is
# per-model, so each model has its own bucket — override via KRONAGENT_TRIAGE_MODEL.
MODEL = os.getenv("KRONAGENT_TRIAGE_MODEL", "gemini-3.1-flash-lite")
MAX_RETRIES = 5          # for 429 / 5xx — routine and expected on the free tier
MAX_TIMEOUT_RETRIES = 1  # for a full-duration hang — a much stronger stall signal;
                          # retrying it 5x at full duration each would block the
                          # sequential pipeline for minutes on one finding
BASE_BACKOFF = 2.0
MAX_BACKOFF = 60.0

# Per-call ceiling. Two layers, deliberately redundant: HttpOptions.timeout is
# passed to the SDK's own HTTP client (best case — a clean transport-level
# timeout), and asyncio.wait_for is an outer guard that forces the coroutine
# to raise even if the SDK's timeout only covers connect (not a stalled read
# with no response ever arriving). Without this, a single stalled request
# blocks the entire sequential pipeline indefinitely — this is not
# hypothetical, it happened in testing: near-zero CPU, no retry log lines, no
# progress for minutes, because nothing had raised yet for the retry loop to
# catch.
REQUEST_TIMEOUT_MS = 45_000
REQUEST_TIMEOUT_SECONDS = REQUEST_TIMEOUT_MS / 1000 + 5  # outer guard, slack for the SDK's own timeout to fire first


async def _with_backoff(factory: Callable[[], Awaitable[T]], *, label: str) -> T:
    attempt = 0
    timeout_attempt = 0
    while True:
        try:
            return await asyncio.wait_for(factory(), timeout=REQUEST_TIMEOUT_SECONDS)
        except (errors.APIError, asyncio.TimeoutError) as exc:
            if isinstance(exc, asyncio.TimeoutError):
                timeout_attempt += 1
                if timeout_attempt > MAX_TIMEOUT_RETRIES:
                    raise
                delay = BASE_BACKOFF
            else:
                status = getattr(exc, "code", None)
                # A daily-quota 429 (free-tier "requests per day") will not clear
                # within any inline backoff — the quota resets on a 24h boundary.
                # Retrying it just delays the inevitable fallback by ~75s per
                # finding. Detect it via the stable `PerDay` quotaId token and
                # fall back immediately; only retry transient per-minute limits.
                if status == 429 and "PerDay" in str(exc):
                    raise
                retryable = status == 429 or (isinstance(status, int) and 500 <= status < 600)
                attempt += 1
                if not retryable or attempt > MAX_RETRIES:
                    raise
                delay = min(BASE_BACKOFF * (2 ** (attempt - 1)), MAX_BACKOFF)
            delay += random.uniform(0, delay * 0.25)
            await asyncio.sleep(delay)


class LLMUnavailableError(RuntimeError):
    """Raised when triage enrichment cannot be produced by the model."""


class TriageLLM(Protocol):
    """What triage, intel, correlation and the commander need from a model."""

    async def structured(self, *, system: str, prompt: str, schema: type[T]) -> T: ...


class GeminiTriageClient:
    def __init__(self, api_key: Optional[str] = None) -> None:
        key = api_key or os.getenv("GEMINI_API_KEY")
        if not key:
            raise LLMUnavailableError("GEMINI_API_KEY is not set")
        self._client = genai.Client(api_key=key)

    async def structured(self, *, system: str, prompt: str, schema: type[T]) -> T:
        config = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_schema=schema,
            temperature=0.1,
            http_options=types.HttpOptions(timeout=REQUEST_TIMEOUT_MS),
        )
        response = await _with_backoff(
            lambda: self._client.aio.models.generate_content(
                model=MODEL, contents=prompt, config=config
            ),
            label="triage",
        )
        parsed = response.parsed
        if isinstance(parsed, schema):
            return parsed
        if response.text:
            return schema.model_validate_json(response.text)
        raise LLMUnavailableError("model returned no parseable structured output")


# Claude in Amazon Bedrock. Model IDs carry the `anthropic.` prefix; access to
# each model is enabled per account in the Bedrock console. Override with
# KRONAGENT_BEDROCK_MODEL (e.g. anthropic.claude-haiku-5-5 for lower cost).
BEDROCK_MODEL = os.getenv("KRONAGENT_BEDROCK_MODEL", "anthropic.claude-opus-5-5")
BEDROCK_MAX_TOKENS = 16_000
BEDROCK_MAX_RETRIES = 2     # the SDK retries 429, 5xx and connection errors itself


class BedrockTriageClient:
    """Claude in Amazon Bedrock through Anthropic's SDK (`anthropic[bedrock]`).

    Credentials and region come from the standard AWS chain: environment, then
    config files, then the ECS task role or instance profile. No key is stored
    anywhere. The output is parsed and validated against `schema` by the SDK;
    a refusal, a truncated answer or an unparseable one raises, and the caller
    falls back exactly as it does for Gemini.
    """

    def __init__(self, *, model: Optional[str] = None, region: Optional[str] = None,
                 client: object | None = None) -> None:
        self.model = model or BEDROCK_MODEL
        if client is not None:
            self._client = client
            return
        try:
            from anthropic import AsyncAnthropicBedrockMantle
        except ImportError as exc:
            raise LLMUnavailableError(
                'Bedrock triage needs the Anthropic SDK: pip install "kronagent[bedrock]"') from exc
        region = region or os.getenv("KRONAGENT_BEDROCK_REGION") or os.getenv("AWS_REGION")
        try:
            self._client = AsyncAnthropicBedrockMantle(
                aws_region=region, timeout=REQUEST_TIMEOUT_MS / 1000, max_retries=BEDROCK_MAX_RETRIES)
        except Exception as exc:  # noqa: BLE001 - no region or no credentials: degrade, don't crash
            raise LLMUnavailableError(f"Bedrock client unavailable: {exc}") from exc

    async def structured(self, *, system: str, prompt: str, schema: type[T]) -> T:
        # The SDK's own timeout and retries cover transport failures; the outer
        # guard is the same one Gemini gets, so a stalled read can never block
        # the sequential pipeline.
        response = await asyncio.wait_for(
            self._client.messages.parse(
                model=self.model,
                max_tokens=BEDROCK_MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                output_format=schema,
            ),
            timeout=REQUEST_TIMEOUT_SECONDS * (BEDROCK_MAX_RETRIES + 1),
        )
        if response.stop_reason == "refusal":
            raise LLMUnavailableError("model declined to answer (refusal)")
        if response.stop_reason == "max_tokens":
            raise LLMUnavailableError("model output was cut off at max_tokens")
        parsed = response.parsed_output
        if isinstance(parsed, schema):
            return parsed
        raise LLMUnavailableError("model returned no parseable structured output")


BACKENDS = ("gemini", "bedrock")


def build_triage_client() -> tuple[TriageLLM, str]:
    """The configured triage model and its model ID, for logs, reports and
    the injection eval's answer cache.

    KRONAGENT_LLM selects the backend: `gemini` (the default) or `bedrock`.
    Raises LLMUnavailableError when the chosen backend can't be used, so the
    pipeline can run deterministic-only instead.
    """
    backend = os.getenv("KRONAGENT_LLM", "gemini").strip().lower()
    if backend == "gemini":
        return GeminiTriageClient(), MODEL
    if backend == "bedrock":
        client = BedrockTriageClient()
        return client, client.model
    raise LLMUnavailableError(f"KRONAGENT_LLM={backend!r} is not one of {', '.join(BACKENDS)}")
