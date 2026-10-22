# Run Kronagent in your AWS account

*One CloudFormation stack. About fifteen minutes. Nothing leaves your account.*

Kronagent reads your GuardDuty findings, works out which ones are real, plans
the containment for each, and asks you in Slack before it acts. This guide puts
all of it inside your own AWS account: the findings, the model calls, the audit
log and the approvals.

It's for a team that has GuardDuty switched on but no one watching it full time.
On the first day, Kronagent can read and plan, and nothing else.

---

## What you get

```
GuardDuty → EventBridge → SQS → Kronagent (one Fargate task) ⇄ Slack
                                   ├ triage: Claude on Amazon Bedrock, in your account
                                   └ state: encrypted EFS, kept even if you delete the stack
```

- **Each finding explained in plain English in Slack,** with the exact
  containment already planned. Approve or deny with one click.
- **No inbound ports.** Nothing on the internet can reach Kronagent. Slack is an
  outbound connection, and the console opens through AWS's own authenticated
  tunnel.
- **Read-only until you decide otherwise.** Kronagent starts with read
  permissions and dry-run on. Write access is one stack parameter, and even
  then every action waits for an approval until you promote an action type to
  run unattended.
- **An audit log you can verify.** Every decision is one record in a SHA-256
  hash chain on the encrypted volume.

**Cost:** about $10–15 a month for Fargate (0.25 vCPU, 1 GB) and EFS, plus
Bedrock tokens per finding. There's no NAT gateway or load balancer. The
default model is Claude Opus 5.5; set `BedrockModel=anthropic.claude-haiku-5-5`
to pay much less per finding.

---

## Before you start

1. **GuardDuty is on** in the region you deploy to. The stack doesn't enable
   it, because an account has one detector per region.
2. **Bedrock model access.** In the Bedrock console, under *Model access*,
   enable the Claude model you'll use (the default is `anthropic.claude-opus-5-5`).
3. **The AWS CLI** with permission to create a stack with IAM resources, plus
   the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
   for reaching the task.
4. **A Slack app** for approvals: five steps in
   [`deploy/slack/README.md`](../deploy/slack/README.md). You'll have an `xapp-`
   token, an `xoxb-` token and a channel ID. You can skip Slack and use the
   console only.

---

## 1. Deploy the stack

Take the template from the release you're installing, so the template and
the image match:

```bash
VERSION=0.2.0
curl -fsSLO "https://raw.githubusercontent.com/Aditya-galaxy/kronagent/v${VERSION}/deploy/cloudformation/kronagent-in-account.json"

aws cloudformation deploy \
  --stack-name kronagent \
  --template-file kronagent-in-account.json \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
      SlackAppToken=xapp-... \
      SlackBotToken=xoxb-... \
      SlackChannelId=C0123456789 \
      SlackUserMapping='{"U0123ABC":"alice"}'
```

`SlackUserMapping` maps your Slack user ID (profile → ⋯ → *Copy member ID*) to
the operator name you'll create in step 2. The tokens go to Secrets Manager. They
are never shown in the console or stored in the template.

## 2. Add yourself as an operator

The operator list starts empty, and an empty list authorizes nobody. No Slack
click counts until you add yourself:

```bash
CLUSTER=$(aws cloudformation describe-stacks --stack-name kronagent \
  --query "Stacks[0].Outputs[?OutputKey=='ClusterName'].OutputValue" --output text)
TASK=$(aws ecs list-tasks --cluster "$CLUSTER" --query 'taskArns[0]' --output text)

aws ecs execute-command --cluster "$CLUSTER" --task "$TASK" --container kronagent \
  --interactive --command "kronagent-operators add alice --roles admin"
```

The same `execute-command` runs the other tools, for example
`kronagent-preflight` (is everything wired?) and `kronagent-approve list`.

## 3. See it work

GuardDuty can generate harmless sample findings:

```bash
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings --detector-id "$DETECTOR" \
  --finding-types UnauthorizedAccess:IAMUser/TorIPCaller
```

Within a minute or two, the task's logs show the triage, and an approval card
appears in your Slack channel. Clicking *Approve* records the decision. In
dry-run, nothing is executed. Logs:

```bash
aws logs tail "$(aws cloudformation describe-stacks --stack-name kronagent \
  --query "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue" --output text)" --follow
```

## 4. Open the console

The console (approval queue, audit log, allowlist) isn't exposed anywhere. Open
it through an authenticated tunnel:

```bash
RUNTIME=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" \
  --query "tasks[0].containers[?name=='kronagent'].runtimeId | [0]" --output text)

aws ssm start-session --target "ecs:${CLUSTER}_${TASK##*/}_${RUNTIME}" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8000"],"localPortNumber":["8000"]}'
```

Then browse to <http://localhost:8000>.

## 5. Let it act, when you're ready

Watch it in dry-run first. A week of findings is a good baseline. Record what
your team actually decided about each finding (`kronagent-outcome record`), and
`kronagent-outcome report` scores Kronagent's calls against yours, listing
every disagreement. `kronagent-digest` renders the week in one page.

Containment needs two resources Kronagent never creates itself: a deny-all
quarantine security group, and a network ACL it may add deny entries to. Both
must be in the VPC you protect. See
[`deploy/README.md` §1](../deploy/README.md#1-prerequisites-to-provision-once-by-a-human-out-of-band).
Then:

```bash
aws cloudformation deploy --stack-name kronagent \
  --template-file kronagent-in-account.json --capabilities CAPABILITY_IAM \
  --parameter-overrides EnableContainment=true \
      QuarantineSecurityGroupId=sg-0123456789abcdef0 QuarantineNaclId=acl-0123456789abcdef0
```

This attaches the least-privilege contain policy, which never includes
terminate, and turns dry-run off. **Every action still waits for an approval.**
To let one action type run unattended, promote it, which is audited. Open a
shell in the task, so your operator token never appears in a command line that
CloudTrail records:

```bash
aws ecs execute-command --cluster "$CLUSTER" --task "$TASK" --container kronagent \
  --interactive --command "bash"
# inside the task:
read -rs KRONAGENT_OPERATOR_TOKEN && export KRONAGENT_OPERATOR_TOKEN
kronagent-promote add disable_access_key --as alice --reason "..." --expires-in 30d
```

Setting `EnableContainment=false` takes write access away again.

## Upgrade

Deploy the next release's template with its version, the same way as step 1.
The stack pins the image to that version, and the service replaces the task
without ever running two at once. Your state on EFS carries over.

## Remove it

```bash
aws cloudformation delete-stack --stack-name kronagent
```

The EFS file system holding the audit log is **kept on purpose**, because it's
your record of what Kronagent did. Delete it in the EFS console once you no
longer need it.

---

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| Triage says `FALLBACK (LLM unavailable)` in the logs | Bedrock refused the call. Usually model access isn't enabled for `BedrockModel` in this region. Kronagent still works on severity alone, and every finding goes to a person. |
| No approval card in Slack | Run `kronagent-preflight` through `execute-command`. Its *Approvals in Slack* section names what's missing: the bot token, the channel, or the bot not invited to the channel. |
| A click answers *not found in operator registry* | Your Slack user ID isn't in `SlackUserMapping`, or that operator wasn't added in step 2. |
| Findings never arrive | Confirm GuardDuty is on in this region and that sample findings were created. The stack's `FindingsQueueUrl` output is the queue they land in. |
| The task restarts repeatedly | The logs show why. Kronagent exits on purpose when its agent loop crashes, so a broken loop never hides behind a healthy-looking console. |

## Licence

Kronagent is source-available under the PolyForm Noncommercial licence, not
open source. Running it for a business needs a commercial licence. Design
partners can request one at licensing@kronagent.com, or through
[kronagent.com](https://kronagent.com).
