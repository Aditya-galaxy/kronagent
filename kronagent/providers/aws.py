"""
AWS provider: GuardDuty normalization + IAM/EC2 containment.

Owns everything vendor-specific about AWS:
  * the GuardDuty finding wire schema (tolerant of unmodeled fields),
  * normalize_guardduty(): GuardDuty finding dict -> provider-neutral Finding,
  * plan_aws_actions(): Finding -> candidate ProposedActions (targets read from
    the finding, never from the LLM),
  * AwsContainmentAdapter: ProposedAction -> concrete boto3 plan / execution.

boto3 is imported lazily inside the adapter so the module (and the whole
pipeline) imports and runs in dry-run with no AWS installed.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..model import Finding, ResourceRef
from ..schemas import ActionClass, ProposedAction

PROVIDER = "aws"

_DENY_ALL_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
    separators=(",", ":"),
)


# --------------------------------------------------------------------------- #
# GuardDuty wire schema (real-schema subset, tolerant of extra fields).
# Nested class names deliberately differ from the JSON field names they type —
# Pydantic degrades a field's annotation to None if a field name shadows a
# same-named class in scope, so field name and type name must never match.
# --------------------------------------------------------------------------- #

class RemoteIp(BaseModel):
    model_config = ConfigDict(extra="allow")
    IpAddressV4: Optional[str] = None
    Organization: Optional[dict[str, Any]] = None
    Country: Optional[dict[str, Any]] = None


class ApiCallAction(BaseModel):
    model_config = ConfigDict(extra="allow")
    Api: Optional[str] = None
    CallerType: Optional[str] = None
    RemoteIpDetails: Optional[RemoteIp] = None


class FindingAction(BaseModel):
    model_config = ConfigDict(extra="allow")
    ActionType: Optional[str] = None
    AwsApiCallAction: Optional[ApiCallAction] = None


class ServiceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    Action: Optional[FindingAction] = None
    Count: Optional[int] = None
    ResourceRole: Optional[str] = None
    EventFirstSeen: Optional[str] = None
    EventLastSeen: Optional[str] = None
    Archived: Optional[bool] = None


class AccessKey(BaseModel):
    model_config = ConfigDict(extra="allow")
    AccessKeyId: Optional[str] = None
    UserName: Optional[str] = None
    UserType: Optional[str] = None


class InstanceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    InstanceId: Optional[str] = None
    NetworkInterfaces: Optional[list[dict[str, Any]]] = None


class ResourceBlock(BaseModel):
    model_config = ConfigDict(extra="allow")
    ResourceType: Optional[str] = None
    AccessKeyDetails: Optional[AccessKey] = None
    InstanceDetails: Optional[InstanceInfo] = None
    S3BucketDetails: Optional[list[dict[str, Any]]] = None


class GuardDutyFinding(BaseModel):
    """Subset of the GuardDuty finding schema, tolerant of unmodeled fields."""

    model_config = ConfigDict(extra="allow")

    Id: str
    AccountId: Optional[str] = None
    Region: Optional[str] = None
    Type: str
    Severity: float  # GuardDuty scale (0.1–8.9+); higher is worse
    Title: Optional[str] = None
    Description: Optional[str] = None
    CreatedAt: Optional[str] = None
    UpdatedAt: Optional[str] = None
    Resource: ResourceBlock = Field(default_factory=ResourceBlock)
    Service: ServiceInfo = Field(default_factory=ServiceInfo)

    @property
    def remote_ip(self) -> Optional[str]:
        act = self.Service.Action
        if act and act.AwsApiCallAction and act.AwsApiCallAction.RemoteIpDetails:
            return act.AwsApiCallAction.RemoteIpDetails.IpAddressV4
        return None


# --------------------------------------------------------------------------- #
# Normalization: GuardDuty dict -> provider-neutral Finding
# --------------------------------------------------------------------------- #

def normalize_guardduty(payload: dict) -> Finding:
    gd = GuardDutyFinding.model_validate(payload)
    resources: list[ResourceRef] = []
    res = gd.Resource
    rtype = (res.ResourceType or "").lower()

    if rtype == "accesskey" and res.AccessKeyDetails:
        akd = res.AccessKeyDetails
        if akd.AccessKeyId:
            resources.append(ResourceRef(
                kind="aws.iam.access_key", id=akd.AccessKeyId,
                attributes={"user_name": akd.UserName or ""},
            ))
        if akd.UserName:
            resources.append(ResourceRef(
                kind="aws.iam.user", id=akd.UserName, attributes={},
            ))
    elif rtype == "instance" and res.InstanceDetails and res.InstanceDetails.InstanceId:
        resources.append(ResourceRef(
            kind="aws.ec2.instance", id=res.InstanceDetails.InstanceId, attributes={},
        ))

    return Finding(
        provider=PROVIDER,
        finding_id=gd.Id,
        finding_type=gd.Type,
        severity=gd.Severity,  # GuardDuty is already ~0-9; no rescale needed
        title=gd.Title or "",
        description=gd.Description or "",
        resources=resources,
        remote_ip=gd.remote_ip,
        raw=payload,
    )


# --------------------------------------------------------------------------- #
# Planning: Finding -> candidate ProposedActions. Targets come from the
# normalized resources, never from model output.
# --------------------------------------------------------------------------- #

def plan_aws_actions(finding: Finding) -> list[ProposedAction]:
    actions: list[ProposedAction] = []

    for r in finding.resources:
        if r.kind == "aws.iam.access_key":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.DISABLE_ACCESS_KEY,
                target=r.id,
                rationale="Deactivate the compromised access key to stop credential abuse.",
                parameters={"user_name": r.attributes.get("user_name", "")},
            ))
        elif r.kind == "aws.iam.user":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL,
                target=r.id,
                rationale="Attach an explicit deny-all policy to halt all further API activity by the principal.",
            ))
        elif r.kind == "aws.ec2.instance":
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.ISOLATE_INSTANCE_SG,
                target=r.id,
                rationale="Swap the instance to a deny-all quarantine security group, preserving it for forensics.",
            ))
            actions.append(ProposedAction(
                provider=PROVIDER, action_class=ActionClass.TERMINATE_INSTANCE,
                target=r.id,
                rationale="Terminate the instance if isolation is insufficient (destructive; approval-gated).",
            ))

    if finding.remote_ip:
        actions.append(ProposedAction(
            provider=PROVIDER, action_class=ActionClass.BLOCK_IP,
            target=finding.remote_ip,
            rationale="Block the remote IP observed driving the malicious API activity.",
        ))

    return actions


# --------------------------------------------------------------------------- #
# Containment adapter: plan (pure) + perform (real boto3).
# --------------------------------------------------------------------------- #

class AwsContainmentAdapter:
    provider = PROVIDER

    def __init__(self, *, region: str, quarantine_security_group_id: str = "",
                 quarantine_nacl_id: str = "",
                 credentials_for: Optional[Callable[[str], Optional[dict]]] = None) -> None:
        """
        credentials_for: given a tenant id, return AWS credentials for that
            tenant's assumed containment role, or None to use whatever the
            process itself holds.

            Omitted, the adapter behaves exactly as before — ambient process
            credentials — which is what local development and the single-tenant
            deployment want. Supplied (see kronagent.connect.CredentialBroker),
            every call runs against the customer's own account under a role
            they granted and can revoke.
        """
        self._region = region
        self._quarantine_sg = quarantine_security_group_id
        self._quarantine_nacl = quarantine_nacl_id
        self._credentials_for = credentials_for
        # Keyed by (tenant, service). One boto3 client per tenant, never shared:
        # a client carries its credentials, so a shared one would silently apply
        # the first tenant's role to every tenant after it.
        self._clients: dict[tuple[str, str], Any] = {}

    def _client(self, service: str, tenant_id: str = "default"):
        key = (tenant_id, service)
        existing = self._clients.get(key)
        if existing is not None:
            return existing

        from ..connect import boto3_client
        creds = self._credentials_for(tenant_id) if self._credentials_for else None
        client = boto3_client(service, region=self._region, credentials=creds)
        self._clients[key] = client
        return client

    def _ec2_client(self, tenant_id: str = "default"):
        return self._client("ec2", tenant_id)

    def _iam_client(self, tenant_id: str = "default"):
        return self._client("iam", tenant_id)

    def invalidate(self, tenant_id: Optional[str] = None) -> None:
        """Drop cached clients so the next call re-resolves credentials.

        Assumed-role credentials expire; the broker refreshes them, but a boto3
        client built with the old ones would keep using them until it failed.
        """
        if tenant_id is None:
            self._clients.clear()
        else:
            for k in [k for k in self._clients if k[0] == tenant_id]:
                self._clients.pop(k, None)

    def plan(self, action: ProposedAction) -> tuple[list[str], str, str]:
        ac = action.action_class
        t = action.target
        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            return (
                [f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Inactive')"],
                f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Active')",
                f"deactivate access key {t}",
            )
        if ac == ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL:
            return (
                [f"iam.put_user_policy(UserName='{t}', PolicyName='kronagent-quarantine-deny-all', PolicyDocument=<deny-all>)"],
                f"iam.delete_user_policy(UserName='{t}', PolicyName='kronagent-quarantine-deny-all')",
                f"attach deny-all inline policy to user {t}",
            )
        if ac == ActionClass.ISOLATE_INSTANCE_SG:
            sg = self._quarantine_sg or "<KRONAGENT_QUARANTINE_SG_ID unset>"
            return (
                [
                    f"ec2.describe_instances(InstanceIds=['{t}'])  # capture original SGs for rollback",
                    f"ec2.modify_instance_attribute(InstanceId='{t}', Groups=['{sg}'])",
                ],
                f"ec2.modify_instance_attribute(InstanceId='{t}', Groups=<original SGs captured at execution>)",
                f"isolate instance {t} into quarantine SG {sg}",
            )
        if ac == ActionClass.BLOCK_IP:
            nacl = self._quarantine_nacl or "<KRONAGENT_QUARANTINE_NACL_ID unset>"
            return (
                [
                    f"ec2.describe_network_acls(NetworkAclIds=['{nacl}'])  # find free rule numbers",
                    f"ec2.create_network_acl_entry(NetworkAclId='{nacl}', RuleNumber=<ingress_rule>, Protocol='-1', RuleAction='deny', Egress=False, CidrBlock='{t}/32')",
                    f"ec2.create_network_acl_entry(NetworkAclId='{nacl}', RuleNumber=<egress_rule>, Protocol='-1', RuleAction='deny', Egress=True, CidrBlock='{t}/32')",
                ],
                f"ec2.delete_network_acl_entry(NetworkAclId='{nacl}', RuleNumber=<ingress_rule>, Egress=False); ec2.delete_network_acl_entry(NetworkAclId='{nacl}', RuleNumber=<egress_rule>, Egress=True)",
                f"block remote IP {t} at the quarantine NACL {nacl}",
            )
        if ac == ActionClass.REVOKE_ROLE_SESSIONS:
            return (
                [f"iam.put_role_policy(RoleName='{t}', PolicyName='kronagent-revoke-sessions', <deny before now>)"],
                f"iam.delete_role_policy(RoleName='{t}', PolicyName='kronagent-revoke-sessions')",
                f"revoke active sessions for role {t}",
            )
        if ac == ActionClass.TERMINATE_INSTANCE:
            return (
                [f"ec2.terminate_instances(InstanceIds=['{t}'])"],
                "IRREVERSIBLE — instance cannot be un-terminated; restore from AMI/snapshot",
                f"terminate instance {t}",
            )
        return ([f"# no AWS planner for {ac.value}"], "unknown", f"unhandled action {ac.value}")

    # ── release: undoing what perform did, when a person asks ─────────────────

    def plan_release(self, action: ProposedAction) -> Optional[tuple[list[str], str]]:
        """The calls a release would make, or None for an action class this
        adapter can't undo yet. Two are supported. Both work from the
        resource's current state, so running one twice does nothing the second
        time."""
        ac, t = action.action_class, action.target
        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            return ([f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Active')"],
                    f"re-activate access key {t}")
        if ac == ActionClass.BLOCK_IP:
            nacl = self._quarantine_nacl or "<KRONAGENT_QUARANTINE_NACL_ID unset>"
            return ([f"ec2.describe_network_acls(NetworkAclIds=['{nacl}'])  # find this address's deny rules",
                     f"ec2.delete_network_acl_entry(NetworkAclId='{nacl}', RuleNumber=<each deny rule for "
                     f"{t}/32>, Egress=<its direction>)"],
                    f"remove the deny rules for {t} from the quarantine NACL {nacl}")
        return None

    async def release(self, action: ProposedAction) -> str:
        return await asyncio.to_thread(self._release_sync, action)

    def _release_sync(self, action: ProposedAction) -> str:
        ac, t, tid = action.action_class, action.target, action.tenant_id
        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            self._aws_call(self._iam_client(tid).update_access_key, UserName=user, AccessKeyId=t, Status="Active")
            return f"access key {t} set Active"
        if ac == ActionClass.BLOCK_IP:
            if not self._quarantine_nacl:
                raise RuntimeError("KRONAGENT_QUARANTINE_NACL_ID is not configured")
            ec2 = self._ec2_client(tid)
            desc = self._aws_call(ec2.describe_network_acls, NetworkAclIds=[self._quarantine_nacl])
            # Only this address's own deny rules. Nothing else in the NACL is
            # touched, whatever its rule numbers were when the block was made.
            ours = [e for e in desc["NetworkAcls"][0]["Entries"]
                    if e.get("CidrBlock") == f"{t}/32" and e.get("RuleAction") == "deny"]
            for entry in ours:
                self._aws_call(ec2.delete_network_acl_entry, NetworkAclId=self._quarantine_nacl,
                               RuleNumber=entry["RuleNumber"], Egress=entry["Egress"])
            if not ours:
                return f"no deny rule for {t} was present in {self._quarantine_nacl}; nothing to remove"
            return f"removed {len(ours)} deny rule(s) for {t} from quarantine NACL {self._quarantine_nacl}"
        raise RuntimeError(f"no release for {ac.value}")

    def _aws_call(self, func, *args, **kwargs):
        import time
        from botocore.exceptions import ClientError
        
        max_retries = 3
        delay = 1.0
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("Throttling", "RequestLimitExceeded", "ThrottlingException"):
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(delay)
                    delay *= 2
                    continue
                if code in ("NoSuchEntity", "NoSuchEntityException"):
                    raise RuntimeError(f"AWS Resource not found: {exc.response.get('Error', {}).get('Message')}") from exc
                if "NotFound" in code or "NoSuch" in code:
                    raise RuntimeError(f"AWS Resource not found: {exc.response.get('Error', {}).get('Message')}") from exc
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                    raise RuntimeError(f"Kronagent IAM Access Denied: {exc.response.get('Error', {}).get('Message')}") from exc
                raise

    async def perform(self, action: ProposedAction) -> tuple[str, str]:
        return await asyncio.to_thread(self._perform_sync, action)

    def _perform_sync(self, action: ProposedAction) -> tuple[str, str]:
        ac = action.action_class
        t = action.target
        # Read once, here. Every client below is resolved for this tenant, so a
        # containment action can only ever touch the account whose finding
        # produced it.
        tid = action.tenant_id
        if ac == ActionClass.DISABLE_ACCESS_KEY:
            user = action.parameters.get("user_name", "")
            self._aws_call(self._iam_client(tid).update_access_key, UserName=user, AccessKeyId=t, Status="Inactive")
            return (f"access key {t} set Inactive",
                    f"iam.update_access_key(UserName='{user}', AccessKeyId='{t}', Status='Active')")
        if ac == ActionClass.ATTACH_DENY_ALL_TO_PRINCIPAL:
            self._aws_call(self._iam_client(tid).put_user_policy,
                UserName=t, PolicyName="kronagent-quarantine-deny-all", PolicyDocument=_DENY_ALL_POLICY
            )
            return (f"deny-all policy attached to {t}",
                    f"iam.delete_user_policy(UserName='{t}', PolicyName='kronagent-quarantine-deny-all')")
        if ac == ActionClass.ISOLATE_INSTANCE_SG:
            if not self._quarantine_sg:
                raise RuntimeError("KRONAGENT_QUARANTINE_SG_ID is not configured")
            ec2 = self._ec2_client(tid)
            desc = self._aws_call(ec2.describe_instances, InstanceIds=[t])
            original = [
                g["GroupId"]
                for r in desc["Reservations"] for i in r["Instances"]
                for g in i.get("SecurityGroups", [])
            ]
            self._aws_call(ec2.modify_instance_attribute, InstanceId=t, Groups=[self._quarantine_sg])
            return (f"instance {t} moved to quarantine SG {self._quarantine_sg} (was {original})",
                    f"ec2.modify_instance_attribute(InstanceId='{t}', Groups={original})")
        if ac == ActionClass.BLOCK_IP:
            if not self._quarantine_nacl:
                raise RuntimeError("KRONAGENT_QUARANTINE_NACL_ID is not configured")
            ec2 = self._ec2_client(tid)
            desc = self._aws_call(ec2.describe_network_acls, NetworkAclIds=[self._quarantine_nacl])
            entries = desc["NetworkAcls"][0]["Entries"]
            ingress_nums = {e["RuleNumber"] for e in entries if not e["Egress"]}
            egress_nums = {e["RuleNumber"] for e in entries if e["Egress"]}

            ingress_rule = next(i for i in range(100, 32767) if i not in ingress_nums)
            egress_rule = next(i for i in range(100, 32767) if i not in egress_nums)

            self._aws_call(ec2.create_network_acl_entry,
                NetworkAclId=self._quarantine_nacl,
                RuleNumber=ingress_rule,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=f"{t}/32",
            )
            self._aws_call(ec2.create_network_acl_entry,
                NetworkAclId=self._quarantine_nacl,
                RuleNumber=egress_rule,
                Protocol="-1",
                RuleAction="deny",
                Egress=True,
                CidrBlock=f"{t}/32",
            )
            return (
                f"remote IP {t} blocked at quarantine NACL {self._quarantine_nacl} (ingress rule {ingress_rule}, egress rule {egress_rule})",
                f"ec2.delete_network_acl_entry(NetworkAclId='{self._quarantine_nacl}', RuleNumber={ingress_rule}, Egress=False); "
                f"ec2.delete_network_acl_entry(NetworkAclId='{self._quarantine_nacl}', RuleNumber={egress_rule}, Egress=True)"
            )
        if ac == ActionClass.REVOKE_ROLE_SESSIONS:
            from datetime import datetime, timezone
            now_str = datetime.now(timezone.utc).isoformat()
            policy_doc = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": now_str
                        }
                    }
                }]
            }, separators=(",", ":"))
            self._aws_call(self._iam_client(tid).put_role_policy,
                RoleName=t,
                PolicyName="kronagent-revoke-sessions",
                PolicyDocument=policy_doc
            )
            return (
                f"active sessions revoked for role {t} (issued before {now_str})",
                f"iam.delete_role_policy(RoleName='{t}', PolicyName='kronagent-revoke-sessions')"
            )
        if ac == ActionClass.TERMINATE_INSTANCE:
            self._aws_call(self._ec2_client(tid).terminate_instances, InstanceIds=[t])
            return (f"instance {t} termination requested", "IRREVERSIBLE — restore from AMI/snapshot")
        raise NotImplementedError(f"real AWS execution for {ac.value} not enabled in this slice")
