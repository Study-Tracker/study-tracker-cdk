from aws_cdk import (
  Stack,
  Environment
)
import os
from constructs import Construct
from cdk_templates.secrets_stack import StudyTrackerSecretsStack
from cdk_templates.study_tracker_application_stack import StudyTrackerCdkStack


class StudyTrackerRootStack(Stack):

  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)


    stage_name = os.environ.get("ST_ENV")
    secret_stack = StudyTrackerSecretsStack(self, "study-tracker-secrets-stack-" + stage_name)
    # secret_utils = SecretUtils(region)
    application_stack = StudyTrackerCdkStack(self, "study-tracker-application-stack-" + stage_name,
                                                  db_root_secret=secret_stack.db_root_secret,
                                                  db_user_secret=secret_stack.db_user_secret,
                                                  elasticsearch_secret=secret_stack.elasticsearch_secret,
                                                  application_secret=secret_stack.application_secret,
                                                  ssl_secret=secret_stack.ssl_secret,
                                                  saml_secret=secret_stack.saml_secret)
