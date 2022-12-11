import boto3
from aws_cdk import (
    Stack,
    aws_secretsmanager as sm
)
from constructs import Construct
import os
import json

application_secret_name = "study-tracker-application-secret-"
ssl_secret_name = "study-tracker-ssl-secret-"
saml_secret_name = "study-tracker-saml-secret-"
db_root_secret_name = "study-tracker-database-root-secret-"
db_user_secret_name = "study-tracker-database-user-secret-"
elasticsearch_secret_name = "study-tracker-elasticsearch-secret-"

class StudyTrackerSecretsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stack = StudyTrackerSecretsStack.of(self)
        stage_name = os.environ.get("ST_ENV")

        sm.Secret(self, application_secret_name + stage_name,
                   description="Encryption key for Study Tracker database",
                   secret_name=application_secret_name + stage_name,
                   generate_secret_string=sm.SecretStringGenerator(
                       password_length=24,
                       exclude_characters="\"'`/\\%$()[]{}<>;|",
                   ))

        sm.Secret(self, ssl_secret_name + stage_name,
                   description="Study Tracker SSL keystore password",
                   secret_name=ssl_secret_name + stage_name,
                  generate_secret_string=sm.SecretStringGenerator(
                      exclude_characters="\"'`/\\%$()[]{}<>;|",
                  ))


        sm.Secret(self, saml_secret_name + stage_name,
                    description="Study Tracker SAML keystore password",
                    secret_name=saml_secret_name + stage_name,
                  generate_secret_string=sm.SecretStringGenerator(
                      exclude_characters="\"'`/\\%$()[]{}<>;|",
                  ))

        sm.Secret(self, db_root_secret_name + stage_name,
                   description="Study Tracker PostgreSQL root user credentials",
                   secret_name=db_root_secret_name + stage_name,
                   generate_secret_string=sm.SecretStringGenerator(
                       password_length=12,
                       exclude_characters="\"'`/\\%$()[]{}<>;|",
                       include_space=False,
                       require_each_included_type=True,
                       generate_string_key="password",
                       secret_string_template=stack.to_json_string({
                           "username": "postgres",
                           "dbname": "postgres",
                           "host": "REPLACE_LATER",
                           "port": "5432"
                       })
                   ))

        sm.Secret(self, db_user_secret_name + stage_name,
                   description="Study Tracker PostgreSQL database user credentials",
                   secret_name=db_user_secret_name + stage_name,
                   generate_secret_string=sm.SecretStringGenerator(
                       password_length=12,
                       exclude_characters="\"'`/\\%$()[]{}<>;|",
                       require_each_included_type=True,
                       include_space=False,
                       generate_string_key="password",
                       secret_string_template=stack.to_json_string({
                           "username": "studytracker",
                           "dbname": "study-tracker",
                           "host": "REPLACE_LATER",
                           "port": "5432"
                       })
                   ))

        sm.Secret(self, elasticsearch_secret_name + stage_name,
                  description="Study Tracker Elasticsearch database credentials",
                  secret_name=elasticsearch_secret_name + stage_name,
                  generate_secret_string=sm.SecretStringGenerator(
                      password_length=12,
                      exclude_characters="\"'`/\\%$()[]{}<>;|",
                      include_space=False,
                      generate_string_key="password",
                      require_each_included_type=True,
                      secret_string_template=stack.to_json_string({
                          "username": "studytracker",
                          "host": "REPLACE_LATER",
                          "port": "443"
                      })
                  ))


class SecretUtils:

    def __init__(self, region):
        """
        Constructs a SecretUtils instance
        :param region: AWS region
        :return:
        """
        session = boto3.session.Session()
        self.client = session.client(service_name="secretsmanager", region_name=region)

    def get_secret_string(self, secret_id, key=None):
        """
        Fetches a secret string value from SecretsManager, given an ARN. If a key is present, the secret will be parsed
        as a JSON object and the key value returned.
        :param secret_id: the secret ARN or name
        :param key: JSON key, if applicable
        :return: string value of the requested secret
        """

        # Fetch the secret value
        secret = self.client.get_secret_value(SecretId=secret_id)
        secret_string = secret["SecretString"]

        # If the whole secret was requested, return it
        if not key:
            return secret_string

        # Make sure the string is JSON formatted
        if not secret_string.trim().starts_with("{"):
            raise Warning("Requested secret is not JSON")

        d = json.loads(secret_string)
        return d[key]

    def get_secret_json(self, secret_id):
        """
        Returns a secret as a dictionary object, parsed from a JSON string
        :param secret_id: the secret ARN
        :return: secret dict
        """
        return json.loads(self.get_secret_string(secret_id))

    def update_secret(self, secret_id, value, key=None):
        """
        Updates a secret value in SecretsManager. If a key is present, the provided secret value will be treated as
        an attribute in a secret's JSON value.
        :param secret_id: the secret ARN or name
        :param value: the new secret string value
        :param key: the JSON key, if applicable
        :return:
        """
        secret_string = self.get_secret_string(secret_id)
        if not key:
            self.client.update_secret(SecretId=secret_id, SecretString=value)
        else:
            d = json.loads(secret_string)
            d[key] = value
            self.client.update_secret(SecretId=secret_id, SecretString=json.dumps(d))