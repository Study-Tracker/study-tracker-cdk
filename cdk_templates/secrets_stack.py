import aws_cdk
from aws_cdk import (
  Stack,
  aws_secretsmanager as sm
)
from constructs import Construct
import os
import json


class StudyTrackerCdkStack(Stack):

  def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    stage_name = os.environ.get("ST_ENV")

    ### Secrets

    st_application_secret = sm.Secret(self, "StudyTrackerApplicationSecret" + stage_name,
                                      description="Encryption key for Study Tracker database",
                                      secret_name="study-tracker-application-secret")

    st_ssl_secret = sm.Secret(self, "StudyTrackerSSLSecret" + stage_name,
                              description="Study Tracker SSL keystore password",
                              secret_name="study-tracker-ssl-secret")

    st_saml_secret = sm.Secret(self, "StudyTrackerSAMLSecret" + stage_name,
                               description="Study Tracker SAML keystore password",
                               secret_name="study-tracker-saml-secret")

    st_db_root_secret = sm.Secret(self, "StudyTrackerDatabaseRootSecret" + stage_name,
                                  description="Study Tracker PostgreSQL root user credentials",
                                  secret_name="study-tracker-db-root-secrets",
                                  generate_secret_string=sm.SecretStringGenerator(
                                    password_length=12,
                                    exclude_characters="\"'`@/\\!%^*()[]{}<>",
                                    include_space=False,
                                    require_each_included_type=True,
                                    generate_string_key="password",
                                    secret_string_template=json.dumps({
                                      "username": "postgres",
                                      "dbname": "postgres",
                                      "host": "REPLACE_LATER",
                                      "port": "5432"
                                    })
                                  ))

    st_db_user_secret = sm.Secret(self, "StudyTrackerDatabaseUserSecret" + stage_name,
                                  description="Study Tracker PostgreSQL database user credentials",
                                  secret_name="study-tracker-db-user-secrets",
                                  generate_secret_string=sm.SecretStringGenerator(
                                    password_length=12,
                                    exclude_characters="\"'`@/\\!%^*()[]{}<>",
                                    require_each_included_type=True,
                                    include_space=False,
                                    generate_string_key="password",
                                    secret_string_template=json.dumps({
                                      "username": "studytracker",
                                      "dbname": "study-tracker",
                                      "host": "REPLACE_LATER",
                                      "port": "5432"
                                    })
                                  ))

    st_es_secret = sm.Secret(self, "StudyTrackerElasticsearchSecret" + stage_name,
                             description="Study Tracker Elasticsearch database credentials",
                             secret_name="study-tracker-elasticsearch-secrets",
                             generate_secret_string=sm.SecretStringGenerator(
                               password_length=12,
                               exclude_characters="\"'`@/\\!%^*()[]{}<>",
                               include_space=False,
                               generate_string_key="password",
                               require_each_included_type=True,
                               secret_string_template=json.dumps({
                                 "username": "studytracker",
                                 "host": "REPLACE_LATER",
                                 "port": "443"
                               })
                             ))