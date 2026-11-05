# Kronagent — Use Cases

*What Kronagent actually does, on three findings you have probably already seen.*

Each scenario below follows the same shape: the finding that arrives, what
responding to it looks like by hand, and what Kronagent does instead — including
where the policy engine stops and waits for you. The trust boundary is part of
the use case, not a footnote to it.

All three run today against replayed real-schema findings in
[`samples/`](../samples). `./demo.sh` walks them end to end.

---

## 1. Leaked access key

**Finding:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
— instance credentials are being used from outside AWS.

**By hand.** You wake up. Work out which credentials. Instance credentials are
temporary (their key starts `ASIA`) and belong to the instance's role, so there
is no key to disable in IAM. What works is denying every session the role issued
before now. Then open CloudTrail, look up everything that key ID touched while
you were asleep, and block the address it came from.

**With Kronagent.** Triage confirms a real credential compromise; threat intel
maps it to ATT&CK T1078. Two actions follow: `revoke_role_sessions` on the
instance's role and `block_ip` on the caller. Forensics captures the role's
policies before they change, and every CloudTrail call made with the stolen key.
For a long-term user key (`AKIA…`) the plan is different and fits it:
`disable_access_key` and a deny-all on that user.

**Where it stops.** Revoking sessions also ends the role's legitimate sessions,
so it is classed destructive and always waits for a person in `approve.py`,
promoted or not. Blocking the IP is reversible and scoped, so an operator can
promote it to run unattended. Nothing else in the account is touched.

---

## 2. Crypto miner on a production EC2 instance

**Finding:** `CryptoCurrency:EC2/BitcoinTool.B!DNS` — an instance is resolving
mining-pool domains.

**By hand.** You know you should kill the box. You also know that terminating it
destroys the evidence, and it is in a production ASG, so killing it may page
someone else. So you sit there at 3am, deciding.

**With Kronagent.** Forensics snapshots the EBS volume first, with chain of
custody recorded, so the evidence survives whatever happens next. Then
`isolate_instance_sg` moves the instance into a pre-provisioned quarantine
security group: network access severed, instance still running and still
inspectable.

**Where it stops.** Quarantine is reversible, so it can auto-execute.
`terminate_instance` is classified destructive and **cannot** run unattended
regardless of allowlist state — promoting it by mistake has no effect. It waits
for a human, with the snapshot already taken.

---

## 3. Compromised pod in a Kubernetes cluster

**Finding:** a Kubernetes audit event showing a pod executing unexpected
binaries and reaching an external address.

**By hand.** `kubectl delete pod` is muscle memory, but the controller
reschedules it and you have destroyed the evidence in exchange for nothing. The
correct move is to isolate it, which means writing a NetworkPolicy at 3am.

**With Kronagent.** Pod logs and the manifest are preserved first. Then
`isolate_pod` applies a deny-all NetworkPolicy over the pod: cut off from the
network, still running, still inspectable, and the controller reschedules
nothing.

**Where it stops.** Isolation is reversible and auto-eligible. `delete_pod` and
`scale_deployment_zero` are destructive and always require human approval.

---

## The pattern

Across all three: evidence is preserved before anything is contained, the
reversible action runs, and the irreversible one waits for a person. Every
decision along the way — triage, policy, approval, containment — is one entry in
the hash-chained audit log, so the whole sequence is reconstructable afterwards.

See [`agent-team-architecture.md`](../agent-team-architecture.md) for why the
policy engine, and not the model, makes every one of these calls.
