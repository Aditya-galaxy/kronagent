"""
The Bedrock triage backend, against a stand-in for the Anthropic SDK client.
No network and no SDK needed: the client is injected.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from kronagent import llm as llm_module
from kronagent.llm import BedrockTriageClient, LLMUnavailableError, build_triage_client
from kronagent.model import Finding
from kronagent.triage import TriageEngine, _LLMTriageOutput

FINDING = Finding(provider="aws", finding_id="f-1", finding_type="UnauthorizedAccess:IAMUser/TorIPCaller",
                  severity=5.0, title="API called from a Tor exit node", description="ListBuckets from Tor.")

ANSWER = _LLMTriageOutput(is_actionable_threat=True, threat_category="credential compromise",
                          confidence=0.9, justification="Tor exit node calling the API.")


class Messages:
    def __init__(self, stop_reason: str = "end_turn", parsed=ANSWER, stall: bool = False) -> None:
        self.stop_reason, self.parsed, self.stall = stop_reason, parsed, stall
        self.calls: list[dict] = []

    async def parse(self, **kwargs):
        self.calls.append(kwargs)
        if self.stall:
            await asyncio.sleep(10)
        return SimpleNamespace(stop_reason=self.stop_reason, parsed_output=self.parsed)


def client(**kw) -> tuple[BedrockTriageClient, Messages]:
    messages = Messages(**kw)
    return BedrockTriageClient(model="anthropic.test-model", client=SimpleNamespace(messages=messages)), messages


def structured(c: BedrockTriageClient):
    return asyncio.run(c.structured(system="sys", prompt="the finding", schema=_LLMTriageOutput))


def test_a_valid_answer_is_returned_as_the_schema() -> None:
    c, messages = client()
    assert structured(c) == ANSWER
    call = messages.calls[0]
    assert call["model"] == "anthropic.test-model"
    assert call["system"] == "sys"
    assert call["messages"] == [{"role": "user", "content": "the finding"}]
    assert call["output_format"] is _LLMTriageOutput
    # Current Claude models reject sampling parameters with a 400.
    assert "temperature" not in call


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
def test_a_refused_or_truncated_answer_is_no_answer(stop_reason: str) -> None:
    c, _ = client(stop_reason=stop_reason)
    with pytest.raises(LLMUnavailableError):
        structured(c)


def test_an_unparseable_answer_is_no_answer() -> None:
    c, _ = client(parsed=None)
    with pytest.raises(LLMUnavailableError):
        structured(c)


def test_a_stalled_call_is_cut_off(monkeypatch) -> None:
    monkeypatch.setattr(llm_module, "REQUEST_TIMEOUT_SECONDS", 0.01)
    c, _ = client(stall=True)
    with pytest.raises(asyncio.TimeoutError):
        structured(c)


def test_a_refusal_falls_back_to_the_severity_verdict() -> None:
    """Triage must fail towards a person, exactly as it does when Gemini is down."""
    c, _ = client(stop_reason="refusal")
    verdict, _ = asyncio.run(TriageEngine(c).assess(FINDING))
    assert verdict.justification.startswith("FALLBACK")
    assert verdict.is_actionable_threat          # severity 5.0 >= 4.0


def test_the_backend_is_chosen_by_env(monkeypatch) -> None:
    built = SimpleNamespace(model="anthropic.claude-haiku-5-5")
    monkeypatch.setattr(llm_module, "BedrockTriageClient", lambda: built)
    monkeypatch.setenv("KRONAGENT_LLM", "Bedrock")
    assert build_triage_client() == (built, "anthropic.claude-haiku-5-5")


def test_an_unknown_backend_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("KRONAGENT_LLM", "openai")
    with pytest.raises(LLMUnavailableError, match="not one of gemini, bedrock"):
        build_triage_client()


def test_gemini_stays_the_default(monkeypatch) -> None:
    monkeypatch.delenv("KRONAGENT_LLM", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(LLMUnavailableError, match="GEMINI_API_KEY"):
        build_triage_client()
