"""
The in-account stack: Kronagent running inside the customer's own AWS account.

The cross-account templates in `connect.py` grant a Kronagent that runs
somewhere else access to the customer's account. This one runs Kronagent
*in* that account instead, so findings, the audit log and the model calls never
leave it, and nobody outside holds a role into it.

    GuardDuty ─► EventBridge rule ─► SQS ─► Fargate task (kronagent-serve)
                                              │  triage on Bedrock (in-account)
                                              │  state on encrypted EFS
                                              └► Slack, outbound only (Socket Mode)

What it is built to guarantee, each one asserted in tests/test_aws_stack.py:

  * **Nothing can reach the task.** Its security group has no inbound rule.
    Approvals come over Slack Socket Mode, and the console is reached with
    ECS Exec port forwarding, which is authenticated by IAM.
  * **Read-only until the customer says otherwise.** The task role carries the
    same observe policy as the cross-account observe role (`_observe_policy`,
    rendered, not copied). The contain policy (`_contain_policy`, the same
    statements as the contain role, no terminate) is attached only when
    EnableContainment=true, and that same switch is the only thing that turns
    dry-run off. Even then, every action still needs an approval or an
    allowlist promotion.
  * **One writer.** The service never runs two tasks at once (maximum 100%),
    because the state files on EFS assume a single process.
  * **State survives.** The audit chain, approvals, allowlist, halt state,
    operator registry, correlation memory and signing key live on EFS, and the
    file system is retained if the stack is deleted, since it is an audit trail.
  * **Secrets stay secret.** Slack tokens are NoEcho parameters stored in
    Secrets Manager and injected as container secrets, never as plain
    environment variables.

Rendered to deploy/cloudformation/kronagent-in-account.json by
deploy/publish_templates.py, which CI checks for drift and lints.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

from typing import Any

from .connect import _cfn_parameterize, _contain_policy, _observe_policy

# The image the stack runs by default. Pinned to a version, never `latest`:
# what a customer installed must not change under them on a task restart.
DEFAULT_IMAGE = "ghcr.io/aditya-galaxy/kronagent:0.2.0"
DEFAULT_BEDROCK_MODEL = "anthropic.claude-opus-5-5"
STATE_DIR = "/var/lib/kronagent"
APP_UID = "10001"            # the image's non-root user
CONSOLE_PORT = 8000

_PARAMETERS: dict[str, dict] = {
    "EnableContainment": {
        "Type": "String",
        "AllowedValues": ["false", "true"],
        "Default": "false",
        "Description": "false: Kronagent can read and plan, and is unable to change anything (no "
                       "write permissions, dry-run). true: attaches the least-privilege contain "
                       "policy and turns dry-run off. Every action still needs an approval in "
                       "Slack or an allowlist promotion.",
    },
    "QuarantineSecurityGroupId": {
        "Type": "String",
        "Default": "",
        "AllowedPattern": "^(sg-[0-9a-f]+)?$",
        "Description": "Required when EnableContainment=true: the deny-all security group "
                       "instances are isolated into. Kronagent can move an instance into this "
                       "group and no other.",
    },
    "QuarantineNaclId": {
        "Type": "String",
        "Default": "",
        "AllowedPattern": "^(acl-[0-9a-f]+)?$",
        "Description": "Required when EnableContainment=true: the network ACL Kronagent may add "
                       "deny entries to. It can modify no other NACL.",
    },
    "BedrockModel": {
        "Type": "String",
        "Default": DEFAULT_BEDROCK_MODEL,
        "Description": "Claude model for triage, via Amazon Bedrock in this account. Enable "
                       "access to it in the Bedrock console first. anthropic.claude-haiku-5-5 "
                       "costs less.",
    },
    "SlackAppToken": {
        "Type": "String",
        "Default": "",
        "NoEcho": True,
        "AllowedPattern": "^(xapp-[A-Za-z0-9-]+)?$",
        "Description": "Slack app-level token (xapp-...) for Socket Mode approvals. Stored in "
                       "Secrets Manager. Leave empty to run without Slack.",
    },
    "SlackBotToken": {
        "Type": "String",
        "Default": "",
        "NoEcho": True,
        "AllowedPattern": "^(xoxb-[A-Za-z0-9-]+)?$",
        "Description": "Slack bot token (xoxb-...) that posts approval cards. Stored in Secrets "
                       "Manager.",
    },
    "SlackChannelId": {
        "Type": "String",
        "Default": "",
        "AllowedPattern": "^([A-Z0-9]+)?$",
        "Description": "Channel the approval cards are posted to, e.g. C0123456789.",
    },
    "SlackUserMapping": {
        "Type": "String",
        "Default": "{}",
        "Description": "JSON mapping Slack user IDs to Kronagent operator IDs, e.g. "
                       "{\"U0123ABC\": \"alice\"}. A click is accepted only from a mapped "
                       "operator in the registry on the state volume.",
    },
    "ImageUri": {
        "Type": "String",
        "Default": DEFAULT_IMAGE,
        "Description": "Kronagent container image. Pin a version.",
    },
    "LogRetentionDays": {
        "Type": "Number",
        "Default": 30,
        "AllowedValues": [7, 14, 30, 60, 90, 180, 365],
        "Description": "How long CloudWatch keeps the task's logs.",
    },
}

_RULES = {
    "ContainmentNeedsQuarantineResources": {
        "RuleCondition": {"Fn::Equals": [{"Ref": "EnableContainment"}, "true"]},
        "Assertions": [
            {"Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": "QuarantineSecurityGroupId"}, ""]}]},
             "AssertDescription": "EnableContainment=true needs QuarantineSecurityGroupId."},
            {"Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": "QuarantineNaclId"}, ""]}]},
             "AssertDescription": "EnableContainment=true needs QuarantineNaclId."},
        ],
    },
    "SocketModeNeedsABotAndAChannel": {
        "RuleCondition": {"Fn::Not": [{"Fn::Equals": [{"Ref": "SlackAppToken"}, ""]}]},
        "Assertions": [
            {"Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": "SlackBotToken"}, ""]}]},
             "AssertDescription": "SlackAppToken needs SlackBotToken, or no card is ever posted."},
            {"Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": "SlackChannelId"}, ""]}]},
             "AssertDescription": "SlackAppToken needs SlackChannelId."},
        ],
    },
}

_CONDITIONS = {
    "ContainmentEnabled": {"Fn::Equals": [{"Ref": "EnableContainment"}, "true"]},
    "HasSlack": {"Fn::Not": [{"Fn::Equals": [{"Ref": "SlackAppToken"}, ""]}]},
}


def _ecs_tasks_trust() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole",
            # Only tasks in this account may assume it (confused-deputy guard).
            "Condition": {"StringEquals": {"aws:SourceAccount": "${AWS::AccountId}"}},
        }],
    }


def _task_policies() -> list[dict]:
    """Everything the task needs besides the observe/contain grants."""
    return [
        {"PolicyName": "KronagentObservePolicy", "PolicyDocument": _observe_policy()},
        {"PolicyName": "KronagentIngestion", "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ReceiveAndDeleteFindingsQueueOnly",
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": "${FindingsQueue.Arn}",
            }],
        }},
        {"PolicyName": "KronagentTriageModel", "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "InvokeClaudeInBedrock",
                "Effect": "Allow",
                "Action": "bedrock-mantle:CreateInference",
                # Which models answer is decided by model access in the Bedrock
                # console and by BedrockModel; this grant only lets the task ask.
                "Resource": "*",
            }],
        }},
        {"PolicyName": "KronagentStateVolume", "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "MountStateThroughItsAccessPointOnly",
                "Effect": "Allow",
                "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                "Resource": "${StateFileSystem.Arn}",
                "Condition": {"StringEquals": {
                    "elasticfilesystem:AccessPointArn": "${StateAccessPoint.Arn}"}},
            }],
        }},
        {"PolicyName": "KronagentEcsExec", "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                # ECS Exec: how an operator reaches the console and the CLIs
                # (operators.py, approve.py, halt.py) without any inbound port.
                "Sid": "EcsExecSessionChannels",
                "Effect": "Allow",
                "Action": ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel",
                           "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"],
                "Resource": "*",
            }],
        }},
    ]


def _environment() -> list[dict]:
    env = {
        "AWS_REGION": "${AWS::Region}",
        "KRONAGENT_STATE_DIR": STATE_DIR,
        "KRONAGENT_DB_PATH": f"{STATE_DIR}/kronagent.db",
        # Set even before the file exists: an empty registry authorizes nobody,
        # so no Slack click is honoured until an operator is added on purpose.
        "KRONAGENT_OPERATOR_REGISTRY": f"{STATE_DIR}/kronagent_operators.json",
        "KRONAGENT_SQS_QUEUE_URL": "${FindingsQueue}",
        "KRONAGENT_LLM": "bedrock",
        "KRONAGENT_BEDROCK_MODEL": "${BedrockModel}",
        "KRONAGENT_QUARANTINE_SG_ID": "${QuarantineSecurityGroupId}",
        "KRONAGENT_QUARANTINE_NACL_ID": "${QuarantineNaclId}",
        "KRONAGENT_SLACK_CHANNEL_ID": "${SlackChannelId}",
        "KRONAGENT_SLACK_USER_MAPPING": "${SlackUserMapping}",
    }
    out = [{"Name": k, "Value": v} for k, v in env.items()]
    # The one switch that turns dry-run off is the one that grants write access.
    out.append({"Name": "KRONAGENT_DRY_RUN",
                "Value": {"Fn::If": ["ContainmentEnabled", "false", "true"]}})
    return out


def _healthcheck() -> dict:
    probe = ("import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("
             f"'http://127.0.0.1:{CONSOLE_PORT}/api/status', timeout=4).status==200 else 1)")
    return {"Command": ["CMD", "python", "-c", probe],
            "Interval": 30, "Timeout": 5, "Retries": 3, "StartPeriod": 30}


def render_stack() -> dict:
    contain = _contain_policy("${AWS::AccountId}", "${AWS::Region}", "${QuarantineNaclId}",
                              "${QuarantineSecurityGroupId}", partition="${AWS::Partition}")
    resources: dict[str, Any] = {
        # ── Network: a small VPC of its own, public subnets, no NAT (no cost).
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
            "CidrBlock": "10.80.0.0/16", "EnableDnsHostnames": True, "EnableDnsSupport": True,
            "Tags": [{"Key": "Name", "Value": "kronagent"}]}},
        "InternetGateway": {"Type": "AWS::EC2::InternetGateway"},
        "GatewayAttachment": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "InternetGateway"}}},
        "PublicRouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
        "PublicRoute": {"Type": "AWS::EC2::Route", "DependsOn": "GatewayAttachment", "Properties": {
            "RouteTableId": {"Ref": "PublicRouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": {"Ref": "InternetGateway"}}},
        **{f"Subnet{x}": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"},
            "CidrBlock": {"Fn::Select": [i, {"Fn::Cidr": ["10.80.0.0/16", 2, 8]}]},
            "AvailabilityZone": {"Fn::Select": [i, {"Fn::GetAZs": ""}]},
            "MapPublicIpOnLaunch": False}} for i, x in enumerate("AB")},
        **{f"Subnet{x}Routes": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
            "SubnetId": {"Ref": f"Subnet{x}"}, "RouteTableId": {"Ref": "PublicRouteTable"}}}
           for x in "AB"},
        "TaskSecurityGroup": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "Kronagent task: no inbound rules at all; outbound HTTPS to AWS and Slack",
            "VpcId": {"Ref": "Vpc"},
            "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0",
                                     "Description": "AWS APIs, Bedrock, Slack, image pulls, EFS"}]}},
        "StateSecurityGroup": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "Kronagent state volume: NFS from the Kronagent task only",
            "VpcId": {"Ref": "Vpc"},
            "SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049,
                                      "SourceSecurityGroupId": {"Ref": "TaskSecurityGroup"},
                                      "Description": "NFS from the Kronagent task"}]}},

        # ── State: encrypted EFS, retained on delete because it is an audit trail.
        "StateFileSystem": {"Type": "AWS::EFS::FileSystem",
                            "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
                            "Properties": {
                                "Encrypted": True,
                                "BackupPolicy": {"Status": "ENABLED"},
                                "FileSystemTags": [{"Key": "Name", "Value": "kronagent-state"}]}},
        **{f"StateMountTarget{x}": {"Type": "AWS::EFS::MountTarget", "Properties": {
            "FileSystemId": {"Ref": "StateFileSystem"}, "SubnetId": {"Ref": f"Subnet{x}"},
            "SecurityGroups": [{"Ref": "StateSecurityGroup"}]}} for x in "AB"},
        "StateAccessPoint": {"Type": "AWS::EFS::AccessPoint", "Properties": {
            "FileSystemId": {"Ref": "StateFileSystem"},
            "PosixUser": {"Uid": APP_UID, "Gid": APP_UID},
            "RootDirectory": {"Path": "/kronagent", "CreationInfo": {
                "OwnerUid": APP_UID, "OwnerGid": APP_UID, "Permissions": "0700"}}}},

        # ── Ingestion: GuardDuty findings → EventBridge → SQS.
        "FindingsDeadLetterQueue": {"Type": "AWS::SQS::Queue", "Properties": {
            "MessageRetentionPeriod": 1209600, "SqsManagedSseEnabled": True}},
        "FindingsQueue": {"Type": "AWS::SQS::Queue", "Properties": {
            "MessageRetentionPeriod": 345600, "VisibilityTimeout": 300,
            "SqsManagedSseEnabled": True,
            "RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["FindingsDeadLetterQueue", "Arn"]},
                              "maxReceiveCount": 5}}},
        "FindingsRule": {"Type": "AWS::Events::Rule", "Properties": {
            "Description": "Every GuardDuty finding in this region, to Kronagent",
            "EventPattern": {"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]},
            "Targets": [{"Arn": {"Fn::GetAtt": ["FindingsQueue", "Arn"]}, "Id": "kronagent"}]}},
        "FindingsQueuePolicy": {"Type": "AWS::SQS::QueuePolicy", "Properties": {
            "Queues": [{"Ref": "FindingsQueue"}],
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Sid": "OnlyTheGuardDutyRuleMaySend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": {"Fn::GetAtt": ["FindingsQueue", "Arn"]},
                "Condition": {"ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["FindingsRule", "Arn"]}}},
            }]}}},

        # ── Secrets.
        "SlackSecret": {"Type": "AWS::SecretsManager::Secret", "Condition": "HasSlack", "Properties": {
            "Description": "Kronagent's Slack tokens (Socket Mode app token and bot token)",
            # A plain string: the parameterize pass below turns it into Fn::Sub.
            # The token parameters' AllowedPatterns keep quotes out of the JSON.
            "SecretString": '{"app_token":"${SlackAppToken}","bot_token":"${SlackBotToken}"}'}},

        # ── Compute.
        "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "RetentionInDays": {"Ref": "LogRetentionDays"}}},
        "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {
            "ClusterSettings": [{"Name": "containerInsights", "Value": "disabled"}]}},
        "ExecutionRole": {"Type": "AWS::IAM::Role", "Properties": {
            "Description": "Pulls the image, writes logs, reads the Slack secret",
            "AssumeRolePolicyDocument": _ecs_tasks_trust(),
            "ManagedPolicyArns": [
                "arn:${AWS::Partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
            "Policies": {"Fn::If": ["HasSlack", [{
                "PolicyName": "ReadSlackSecret",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
                    "Resource": {"Ref": "SlackSecret"}}]}}], {"Ref": "AWS::NoValue"}]}}},
        "TaskRole": {"Type": "AWS::IAM::Role", "Properties": {
            "Description": "Kronagent itself: read-only unless EnableContainment=true",
            "AssumeRolePolicyDocument": _ecs_tasks_trust(),
            "Policies": _task_policies()}},
        "ContainPolicy": {"Type": "AWS::IAM::RolePolicy", "Condition": "ContainmentEnabled", "Properties": {
            "PolicyName": "KronagentContainPolicy",
            "RoleName": {"Ref": "TaskRole"},
            "PolicyDocument": contain}},
        "TaskDefinition": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
            "Family": "kronagent",
            "Cpu": "256", "Memory": "1024",
            "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"],
            "RuntimePlatform": {"CpuArchitecture": "X86_64", "OperatingSystemFamily": "LINUX"},
            "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
            "TaskRoleArn": {"Fn::GetAtt": ["TaskRole", "Arn"]},
            "Volumes": [{"Name": "state", "EFSVolumeConfiguration": {
                "FilesystemId": {"Ref": "StateFileSystem"},
                "TransitEncryption": "ENABLED",
                "AuthorizationConfig": {"AccessPointId": {"Ref": "StateAccessPoint"}, "IAM": "ENABLED"}}}],
            "ContainerDefinitions": [{
                "Name": "kronagent",
                "Image": {"Ref": "ImageUri"},
                "Essential": True,
                "MountPoints": [{"SourceVolume": "state", "ContainerPath": STATE_DIR}],
                "Environment": _environment(),
                "Secrets": {"Fn::If": ["HasSlack", [
                    {"Name": "KRONAGENT_SLACK_APP_TOKEN", "ValueFrom": "${SlackSecret}:app_token::"},
                    {"Name": "KRONAGENT_SLACK_BOT_TOKEN", "ValueFrom": "${SlackSecret}:bot_token::"},
                ], {"Ref": "AWS::NoValue"}]},
                "HealthCheck": _healthcheck(),
                # ECS Exec needs an init process to reap the sessions it starts.
                "LinuxParameters": {"InitProcessEnabled": True},
                "LogConfiguration": {"LogDriver": "awslogs", "Options": {
                    "awslogs-group": {"Ref": "LogGroup"},
                    "awslogs-region": {"Ref": "AWS::Region"},
                    "awslogs-stream-prefix": "kronagent"}},
            }],
        }},
        "Service": {"Type": "AWS::ECS::Service",
                    "DependsOn": ["PublicRoute", "StateMountTargetA", "StateMountTargetB"],
                    "Properties": {
                        "Cluster": {"Ref": "Cluster"},
                        "TaskDefinition": {"Ref": "TaskDefinition"},
                        "DesiredCount": 1,
                        "LaunchType": "FARGATE",
                        "EnableExecuteCommand": True,
                        # One task at a time, always: the state on EFS assumes a
                        # single writer, so a deploy stops the old task first.
                        "DeploymentConfiguration": {
                            "MaximumPercent": 100, "MinimumHealthyPercent": 0,
                            "DeploymentCircuitBreaker": {"Enable": True, "Rollback": True}},
                        "NetworkConfiguration": {"AwsvpcConfiguration": {
                            "AssignPublicIp": "ENABLED",
                            "SecurityGroups": [{"Ref": "TaskSecurityGroup"}],
                            "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]}}}},
    }
    outputs = {
        "ClusterName": {"Description": "ECS cluster running Kronagent", "Value": {"Ref": "Cluster"}},
        "ServiceName": {"Description": "ECS service", "Value": {"Fn::GetAtt": ["Service", "Name"]}},
        "FindingsQueueUrl": {"Description": "Where GuardDuty findings queue for Kronagent",
                             "Value": {"Ref": "FindingsQueue"}},
        "LogGroupName": {"Description": "Kronagent's logs", "Value": {"Ref": "LogGroup"}},
        "StateFileSystemId": {"Description": "EFS holding the audit log and state (retained on delete)",
                              "Value": {"Ref": "StateFileSystem"}},
        "ContainmentEnabled": {"Description": "Whether Kronagent holds write permissions",
                               "Value": {"Ref": "EnableContainment"}},
    }
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Kronagent inside your AWS account: triages GuardDuty findings with Claude "
                       "on Bedrock, plans containment, and asks in Slack before acting. Read-only "
                       "by default. No inbound ports.",
        "Parameters": _PARAMETERS,
        "Rules": _RULES,
        "Conditions": _CONDITIONS,
        "Resources": resources,
        "Outputs": outputs,
    }
    return _cfn_parameterize(body, set(_PARAMETERS))
