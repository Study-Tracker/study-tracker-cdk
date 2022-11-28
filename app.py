#!/usr/bin/env python3
import aws_cdk as cdk
from cdk_templates.study_tracker_cdk_stack import StudyTrackerCdkStack
import os

stage_name = os.environ.get("ST_ENV")
app = cdk.App()
env = cdk.Environment(account=os.environ.get("AWS_ACCOUNT_ID"),
                      region=os.environ.get("AWS_REGION"))
StudyTrackerCdkStack(app, "StudyTrackerCdkStack-" + stage_name, env=env)

app.synth()
