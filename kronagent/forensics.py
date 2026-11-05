"""
Forensics Agent — evidence collection with chain of custody.

Per agent-team-architecture.md §2 ("not every agent is an LLM") and §4
(Forensics listed as an agent, but gated on real execution), this agent is
DETERMINISTIC, not an LLM. Which evidence to collect for a compromised resource
is computable from the finding — an EC2 instance gets an EBS snapshot + instance
metadata + CloudTrail history; a pod gets its logs + manifest + node context.
The evidence targets come from the finding's normalized resources, never from a
model, so — exactly like containment — a prompt-injection payload in telemetry
cannot redirect evidence collection (or a destructive snapshot) onto an
attacker-chosen resource.

The real capability here is not "run a snapshot command" — it's **chain of
custody**. Every piece of evidence is recorded with what it is, where it came
from, when it was collected, by whom, and a SHA-256 custody hash, into the
platform's append-only hash-chained audit log. That log already provides
tamper-evidence for the whole decision trail; routing custody records through
it means the evidence log inherits the same property — an after-the-fact edit
to a custody record breaks chain verification. That is precisely what "chain of
custody" requires for evidence to be admissible / defensible.

Dry-run discipline (identical to the containment executor): the evidence PLAN
and the custody record are computed and written for every actionable finding,
always. Actual collection (the boto3 / kubernetes calls) runs only when
dry_run is off. So in dry-run you get a complete, auditable, custody-tracked
record of exactly what evidence WOULD be collected, with nothing touched — and
the same code path collects for real once execution is enabled.

Ordering: forensics runs BEFORE containment in the pipeline, so evidence is
preserved before a containment action can alter the resource's state (you
snapshot the instance before you isolate or terminate it).
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from .audit import AuditLog
from .config import Settings
from .crypto import get_signer, Signer
from .model import Finding
from .schemas import AuditRecord

COLLECTOR = "kronagent-forensics"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: "evd-" + uuid.uuid4().hex[:12])
    kind: str                       # e.g. "aws.ebs.snapshot", "k8s.pod.logs"
    target: str                     # the concrete resource id, from the finding
    description: str
    collection_calls: list[str] = Field(default_factory=list)  # concrete commands (planned/run)
    read_only: bool = True          # False => collection mutates state (e.g. create_snapshot)
    collected: bool = False         # False in dry-run/plan-only
    collected_at: str = Field(default_factory=_now)
    collector: str = COLLECTOR
    custody_sha256: str = ""        # hash of the custody manifest (this record's identity)
    custody_signature: str = ""     # cryptographic signature of custody_sha256
    artifact_sha256: str = ""       # hash of the collected artifact bytes, populated on live collection

    def custody_manifest(self) -> dict:
        """The canonical descriptor the custody hash is computed over. Excludes
        the hash itself and mutable execution results."""
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "target": self.target,
            "collection_calls": self.collection_calls,
            "collected_at": self.collected_at,
            "collector": self.collector,
        }

    def with_custody_hash(self) -> "EvidenceItem":
        manifest = json.dumps(self.custody_manifest(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        return self.model_copy(update={"custody_sha256": digest})

    def with_custody_signature(self, signer: Signer) -> "EvidenceItem":
        import base64
        item = self if self.custody_sha256 else self.with_custody_hash()
        sig_bytes = signer.sign(item.custody_sha256.encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
        return item.model_copy(update={"custody_signature": sig_b64})

    def verify_custody(self, signer: Signer | None = None) -> bool:
        """Returns True if the custody_sha256 matches the current manifest
        and verifies the cryptographic signature if a signer is supplied."""
        manifest = json.dumps(self.custody_manifest(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        if self.custody_sha256 != digest:
            return False

        if signer is not None and self.custody_signature:
            import base64
            try:
                sig_bytes = base64.b64decode(self.custody_signature)
                return signer.verify(digest.encode("utf-8"), sig_bytes)
            except Exception:
                return False
        return True


class ForensicsResult(BaseModel):
    finding_id: str
    provider: str
    items: list[EvidenceItem] = Field(default_factory=list)

    def evidence_kinds(self) -> list[str]:
        return [i.kind for i in self.items]


# --------------------------------------------------------------------------- #
# Deterministic evidence planning, keyed on the normalized resource kind.
# Targets come from finding.resources — never from a model.
# --------------------------------------------------------------------------- #

def _plan_aws_evidence(finding: Finding) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for r in finding.resources:
        if r.kind == "aws.ec2.instance":
            items.append(EvidenceItem(
                kind="aws.ebs.snapshot", target=r.id, read_only=False,
                description=f"Snapshot the EBS volumes of instance {r.id} for offline forensic analysis.",
                collection_calls=[
                    f"ec2.describe_instances(InstanceIds=['{r.id}'])  # enumerate attached volumes",
                    f"ec2.create_snapshot(VolumeId=<each>, Description='kronagent-forensic {r.id}', TagSpecifications=[kronagent:evidence])",
                ],
            ))
            items.append(EvidenceItem(
                kind="aws.ec2.metadata", target=r.id, read_only=True,
                description=f"Capture instance metadata and network config for {r.id}.",
                collection_calls=[f"ec2.describe_instances(InstanceIds=['{r.id}'])"],
            ))
            items.append(EvidenceItem(
                kind="aws.cloudtrail.history", target=r.id, read_only=True,
                description=f"Recent CloudTrail activity referencing instance {r.id}.",
                collection_calls=[f"cloudtrail.lookup_events(LookupAttributes=[ResourceName='{r.id}'])"],
            ))
        elif r.kind in ("aws.iam.access_key", "aws.iam.user"):
            principal = r.attributes.get("user_name") or r.id
            items.append(EvidenceItem(
                kind="aws.cloudtrail.history", target=principal, read_only=True,
                description=f"Recent CloudTrail activity for principal {principal}.",
                collection_calls=[f"cloudtrail.lookup_events(LookupAttributes=[Username='{principal}'])"],
            ))
        elif r.kind in ("aws.sts.temporary_credentials", "aws.iam.root_access_key"):
            # Temporary credentials are traced by key, not by name: CloudTrail
            # records the session name, which an attacker using stolen tokens
            # does not choose and a defender rarely knows.
            items.append(EvidenceItem(
                kind="aws.cloudtrail.history", target=r.id, read_only=True,
                description=f"Every CloudTrail call made with access key {r.id}.",
                collection_calls=[f"cloudtrail.lookup_events(LookupAttributes=[AccessKeyId='{r.id}'])"],
            ))
        elif r.kind == "aws.iam.role":
            items.append(EvidenceItem(
                kind="aws.iam.role.state", target=r.id, read_only=True,
                description="The role's trust and permission policies before containment changes them.",
                collection_calls=[f"iam.get_role(RoleName='{r.id}')",
                                  f"iam.list_role_policies(RoleName='{r.id}')",
                                  f"iam.list_attached_role_policies(RoleName='{r.id}')"],
            ))
    return items


def _plan_k8s_evidence(finding: Finding) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for r in finding.resources:
        if r.kind == "k8s.pod":
            ns = r.attributes.get("namespace", "default")
            items.append(EvidenceItem(
                kind="k8s.pod.logs", target=r.id, read_only=True,
                description=f"Capture logs of pod {ns}/{r.id} (all containers, previous instances).",
                collection_calls=[f"kubectl logs {r.id} -n {ns} --all-containers --previous --timestamps"],
            ))
            items.append(EvidenceItem(
                kind="k8s.pod.manifest", target=r.id, read_only=True,
                description=f"Capture the live manifest and status of pod {ns}/{r.id}.",
                collection_calls=[f"kubectl get pod {r.id} -n {ns} -o yaml"],
            ))
        elif r.kind == "k8s.node":
            items.append(EvidenceItem(
                kind="k8s.node.describe", target=r.id, read_only=True,
                description=f"Capture node {r.id} status, conditions, and scheduled pods.",
                collection_calls=[f"kubectl describe node {r.id}"],
            ))
        elif r.kind == "k8s.deployment":
            ns = r.attributes.get("namespace", "default")
            items.append(EvidenceItem(
                kind="k8s.deployment.manifest", target=r.id, read_only=True,
                description=f"Capture the manifest of deployment {ns}/{r.id}.",
                collection_calls=[f"kubectl get deployment {r.id} -n {ns} -o yaml"],
            ))
    return items


_PLANNERS = {
    "aws": _plan_aws_evidence,
    "kubernetes": _plan_k8s_evidence,
}


class ForensicsAgent:
    """Plans evidence collection, records chain of custody into the audit log,
    and — when dry_run is off — performs the collection."""

    def __init__(self, settings: Settings, signer: Signer | None = None) -> None:
        self._dry_run = settings.dry_run
        self._signer = signer or get_signer(settings)

    async def collect(self, finding: Finding, audit: AuditLog) -> ForensicsResult:
        planner = _PLANNERS.get(finding.provider)
        raw_items = planner(finding) if planner else []

        # De-duplicate by (kind, target). A finding can implicate the same
        # underlying subject through several resources — e.g. an access key AND
        # the IAM user that owns it both resolve to one principal, so the naive
        # plan collects that principal's CloudTrail history twice. Duplicate
        # collection wastes API calls and, worse, writes two custody records for
        # one piece of evidence, which muddies the chain of custody.
        seen: set[tuple[str, str]] = set()
        deduped: list[EvidenceItem] = []
        for item in raw_items:
            key = (item.kind, item.target)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        recorded: list[EvidenceItem] = []
        for item in deduped:
            # Stamp the custody hash and signature before anything else — it's the evidence's
            # identity and must be fixed at plan time, not after collection.
            item = item.with_custody_hash()
            item = item.with_custody_signature(self._signer)

            if not self._dry_run:
                # Real collection would run item.collection_calls here via the
                # provider client and populate artifact_sha256 from the collected
                # bytes. Not enabled in this slice (no live account/cluster) — the
                # plan + custody record are produced exactly as they would be for
                # real collection; only the byte-level artifact hashing is
                # deferred until execution is wired.
                item = item.model_copy(update={
                    "collected": False,
                    "description": item.description + " [LIVE collection not yet wired — plan + custody recorded]",
                })

            recorded.append(item)

            # Chain of custody: every evidence item is written to the append-only,
            # hash-chained audit log. The log's own chain makes the custody record
            # tamper-evident — editing it after the fact breaks verification.
            await audit.record(AuditRecord(
                finding_id=finding.finding_id, stage="forensics",
                payload={
                    "evidence_id": item.evidence_id,
                    "kind": item.kind,
                    "target": item.target,
                    "read_only": item.read_only,
                    "collected": item.collected,
                    "collected_at": item.collected_at,
                    "collector": item.collector,
                    "custody_sha256": item.custody_sha256,
                    "custody_signature": item.custody_signature,
                    "artifact_sha256": item.artifact_sha256,
                    "collection_calls": item.collection_calls,
                    "dry_run": self._dry_run,
                },
            ))

        return ForensicsResult(finding_id=finding.finding_id, provider=finding.provider, items=recorded)
