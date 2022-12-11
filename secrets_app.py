#!/usr/bin/env python3
import aws_cdk as cdk
from cdk_templates.secrets_stack import StudyTrackerSecretsStack
import os

stage_name = os.environ.get("ST_ENV")
account_id = os.environ.get("AWS_ACCOUNT_ID")
region = os.environ.get("AWS_REGION")
app = cdk.App()
env = cdk.Environment(account=account_id, region=region)
secrets_stack = StudyTrackerSecretsStack(app, "study-tracker-secrets-stack-" + stage_name, env=env)
app.synth()
