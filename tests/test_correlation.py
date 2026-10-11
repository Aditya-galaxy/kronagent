"""
Investigation / Correlation Agent + its memory.

The agent itself is tested with a fake LLM (no network). The memory (the
bounded rolling window) is tested directly. The safety-critical property here
is the same as every advisory agent: it can never emit an execution decision,
and it can never point at a finding that wasn't actually in its history (no
hallucinated correlations survive).
"""

from __future__ import annotations

import pytest

from kronagent.correlation import (
    CorrelationAgent,
    CorrelationMemory,
    FindingSummary,
    RelatedFinding,
    _LLMCorrelationOutput,
)
from kronagent.model import Finding, ResourceRef


def _finding(finding_id: str, *, provider: str = "aws", severity: float = 8.0,
             ip: str | None = None, resources: list[ResourceRef] | None = None) -> Finding:
    return Finding(
        provider=provider, finding_id=finding_id, finding_type="Test", severity=severity,
        remote_ip=ip, resources=resources or [],
    )


# --------------------------------------------------------------------------- #
# CorrelationMemory
# --------------------------------------------------------------------------- #

def test_memory_records_and_summarizes_findings() -> None:
    mem = CorrelationMemory()
    mem.add(_finding("f-1", ip="1.2.3.4", resources=[ResourceRef(kind="aws.iam.user", id="alice")]))
    prior = mem.prior_to("other")
    assert len(prior) == 1
    assert isinstance(prior[0], FindingSummary)
    assert prior[0].finding_id == "f-1"
    assert prior[0].remote_ip == "1.2.3.4"
    assert prior[0].resource_ids == ["alice"]


def test_memory_prior_to_excludes_self() -> None:
    mem = CorrelationMemory()
    mem.add(_finding("f-1"))
    mem.add(_finding("f-2"))
    prior = mem.prior_to("f-2")
    assert [s.finding_id for s in prior] == ["f-1"]


def test_memory_is_bounded_and_evicts_oldest() -> None:
    mem = CorrelationMemory(maxlen=3, capacity=3)
    for i in range(5):
        mem.add(_finding(f"f-{i}"))
    ids = [s.finding_id for s in mem.prior_to("none")]
    assert ids == ["f-2", "f-3", "f-4"]  # oldest two evicted
    assert len(mem) == 3


def test_what_is_shown_is_smaller_than_what_is_kept() -> None:
    """`maxlen` bounds one assessment's history, not the memory. When they were
    the same number, 25 noisy findings were enough to flush a real one."""
    mem = CorrelationMemory(maxlen=3)
    for i in range(5):
        mem.add(_finding(f"f-{i}"))
    assert [s.finding_id for s in mem.prior_to("none")] == ["f-2", "f-3", "f-4"]
    assert len(mem) == 5


# --------------------------------------------------------------------------- #
# CorrelationAgent — degradation paths (no network)
# --------------------------------------------------------------------------- #

async def test_no_llm_returns_unavailable() -> None:
    agent = CorrelationAgent(llm=None)
    result = await agent.assess(_finding("f-1"), prior=[FindingSummary(
        finding_id="f-0", provider="aws", finding_type="T", severity=5.0)])
    assert result.available is False
    assert result.part_of_campaign is False


async def test_empty_history_returns_unavailable_without_calling_llm() -> None:
    """Correlation is meaningless with nothing to correlate against -- must not
    even call the LLM (cost discipline)."""
    class ExplodingLLM:
        async def structured(self, **kwargs):
            pytest.fail("LLM must not be called when history is empty")

    agent = CorrelationAgent(llm=ExplodingLLM())
    result = await agent.assess(_finding("f-1"), prior=[])
    assert result.available is False


# --------------------------------------------------------------------------- #
# CorrelationAgent — with a scripted LLM
# --------------------------------------------------------------------------- #

class ScriptedLLM:
    """Returns a fixed _LLMCorrelationOutput, ignoring the prompt."""

    def __init__(self, output: _LLMCorrelationOutput) -> None:
        self._output = output
        self.calls = 0

    async def structured(self, *, system, prompt, schema):
        self.calls += 1
        return self._output


async def test_campaign_detected_with_valid_related_id() -> None:
    prior = [FindingSummary(finding_id="f-0", provider="aws", finding_type="CredExfil", severity=8.0)]
    llm = ScriptedLLM(_LLMCorrelationOutput(
        part_of_campaign=True,
        related=[RelatedFinding(finding_id="f-0", relationship="same source IP")],
        campaign_narrative="Same actor pivoting from credential theft.",
        correlation_summary="Linked to f-0 via shared source IP.",
    ))
    agent = CorrelationAgent(llm=llm)
    result = await agent.assess(_finding("f-1"), prior=prior)

    assert result.available is True
    assert result.part_of_campaign is True
    assert result.related_finding_ids == ["f-0"]
    assert "same actor" in result.campaign_narrative.lower()


async def test_hallucinated_related_id_is_dropped() -> None:
    """The model must not be able to correlate with a finding that was never in
    its history -- a defensive filter, since a phantom correlation in an
    incident record is a real integrity problem."""
    prior = [FindingSummary(finding_id="f-0", provider="aws", finding_type="T", severity=8.0)]
    llm = ScriptedLLM(_LLMCorrelationOutput(
        part_of_campaign=True,
        related=[
            RelatedFinding(finding_id="f-0", relationship="real"),
            RelatedFinding(finding_id="f-HALLUCINATED", relationship="does not exist"),
        ],
        campaign_narrative="...",
        correlation_summary="...",
    ))
    agent = CorrelationAgent(llm=llm)
    result = await agent.assess(_finding("f-1"), prior=prior)

    assert result.related_finding_ids == ["f-0"]  # phantom dropped
    assert all(r.finding_id == "f-0" for r in result.related)


async def test_campaign_flag_requires_a_surviving_related_finding() -> None:
    """If the model says 'part_of_campaign' but every related id it cited was
    hallucinated (and thus filtered), the campaign claim must NOT stand -- there
    is nothing real to back it."""
    prior = [FindingSummary(finding_id="f-0", provider="aws", finding_type="T", severity=8.0)]
    llm = ScriptedLLM(_LLMCorrelationOutput(
        part_of_campaign=True,
        related=[RelatedFinding(finding_id="f-PHANTOM", relationship="fake")],
        campaign_narrative="...",
        correlation_summary="...",
    ))
    agent = CorrelationAgent(llm=llm)
    result = await agent.assess(_finding("f-1"), prior=prior)

    assert result.related_finding_ids == []
    assert result.part_of_campaign is False


async def test_unrelated_finding_reports_no_campaign() -> None:
    prior = [FindingSummary(finding_id="f-0", provider="aws", finding_type="T", severity=8.0)]
    llm = ScriptedLLM(_LLMCorrelationOutput(
        part_of_campaign=False, related=[], campaign_narrative="",
        correlation_summary="No correlation with recent findings.",
    ))
    agent = CorrelationAgent(llm=llm)
    result = await agent.assess(_finding("f-1"), prior=prior)

    assert result.available is True
    assert result.part_of_campaign is False
    assert result.related_finding_ids == []


async def test_llm_exception_degrades_to_unavailable() -> None:
    class RaisingLLM:
        async def structured(self, **kwargs):
            raise RuntimeError("model exploded")

    prior = [FindingSummary(finding_id="f-0", provider="aws", finding_type="T", severity=8.0)]
    agent = CorrelationAgent(llm=RaisingLLM())
    result = await agent.assess(_finding("f-1"), prior=prior)
    assert result.available is False


def test_correlation_output_schema_has_no_action_field() -> None:
    """Structural safety guarantee: the schema the model fills cannot express a
    containment target or action -- so this agent literally cannot emit one."""
    fields = set(_LLMCorrelationOutput.model_fields)
    forbidden = {"target", "action", "action_class", "resource", "provider", "command"}
    assert fields.isdisjoint(forbidden)
    assert fields == {"part_of_campaign", "related", "campaign_narrative", "correlation_summary"}
