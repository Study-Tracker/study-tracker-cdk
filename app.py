#!/usr/bin/env python3
import aws_cdk as cdk
from cdk_templates.study_tracker_application_stack import StudyTrackerCdkStack
import os

stage_name = os.environ.get("ST_ENV")
account_id = os.environ.get("AWS_ACCOUNT_ID")
region = os.environ.get("AWS_REGION")
app = cdk.App()
env = cdk.Environment(account=account_id, region=region)
root_stack = StudyTrackerCdkStack(app, "study-tracker-application-stack-" + stage_name,
                                  env=env,
                                  description="Study Tracker application stack. Includes EC2, S3 bucket, RDS instance, ElasticSearch instance, secretes, and more.",
                                  tags={"BillingProject": "Study Tracker", "BillingStage": stage_name}
                                  )
app.synth()
