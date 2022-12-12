from aws_cdk import (
  Stack,
  aws_rds as rds,
)
import os
from constructs import Construct


class StudyTrackerRdsStack(Stack):

  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    stack = StudyTrackerRdsStack.of(self)
    stage_name = os.environ.get("ST_ENV")