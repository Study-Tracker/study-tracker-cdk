import aws_cdk
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_events as events,
    aws_s3 as s3,
    aws_iam as iam,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_opensearchservice as es,
    aws_secretsmanager as sm
)
from constructs import Construct
import os

application_secret_name = "study-tracker-application-secret-"
ssl_secret_name = "study-tracker-ssl-secret-"
saml_secret_name = "study-tracker-saml-secret-"
db_root_secret_name = "study-tracker-database-root-secret-"
db_user_secret_name = "study-tracker-database-user-secret-"
elasticsearch_secret_name = "study-tracker-elasticsearch-secret-"


class StudyTrackerCdkStack(Stack):

    def __init__(
            self,
            scope: Construct,
            construct_id: str,
            **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stage_name = os.environ.get("ST_ENV")
        production_mode = bool(os.environ.get("PRODUCTION_MODE", "False"))

        ### Secrets
        stack = StudyTrackerCdkStack.of(self)

        application_secret = sm.Secret(self, "StudyTrackerApplicationSecret" + stage_name,
                                            description="Encryption key for Study Tracker database",
                                            secret_name=application_secret_name + stage_name,
                                            generate_secret_string=sm.SecretStringGenerator(
                                                password_length=24,
                                                exclude_characters="\"'`/\\%$()[]{}<>;|!",
                                            ))

        ssl_secret = sm.Secret(self, "StudyTrackerSSLSecret" + stage_name,
                                    description="Study Tracker SSL keystore password",
                                    secret_name=ssl_secret_name + stage_name,
                                    generate_secret_string=sm.SecretStringGenerator(
                                        exclude_characters="\"'`/\\%$()[]{}<>;|!",
                                    ))

        saml_secret = sm.Secret(self, "StudyTrackerSAMLSecret" + stage_name,
                                     description="Study Tracker SAML keystore password",
                                     secret_name=saml_secret_name + stage_name,
                                     generate_secret_string=sm.SecretStringGenerator(
                                         exclude_characters="\"'`/\\%$()[]{}<>;|!",
                                     ))

        db_root_secret = sm.Secret(self, "StudyTrackerDBRootSecret" + stage_name,
                                        description="Study Tracker PostgreSQL root user credentials",
                                        secret_name=db_root_secret_name + stage_name,
                                        generate_secret_string=sm.SecretStringGenerator(
                                            password_length=24,
                                            exclude_characters="\"'`/\\%$()[]{}<>;|!@",
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

        db_user_secret = sm.Secret(self, "StudyTrackerDBUserSecret" + stage_name,
                                        description="Study Tracker PostgreSQL database user credentials",
                                        secret_name=db_user_secret_name + stage_name,
                                        generate_secret_string=sm.SecretStringGenerator(
                                            password_length=24,
                                            exclude_characters="\"'`/\\%$()[]{}<>;|!@",
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

        elasticsearch_secret = sm.Secret(self, "StudyTrackerElasticSearchSecret" + stage_name,
                                              description="Study Tracker Elasticsearch database credentials",
                                              secret_name=elasticsearch_secret_name + stage_name,
                                              generate_secret_string=sm.SecretStringGenerator(
                                                  password_length=24,
                                                  exclude_punctuation=True,
                                                  include_space=False,
                                                  generate_string_key="password",
                                                  require_each_included_type=True,
                                                  secret_string_template=stack.to_json_string({
                                                      "username": "studytracker",
                                                      "host": "REPLACE_LATER",
                                                      "port": "443"
                                                  })
                                              ))


        ### VPC
        vpc = ec2.Vpc.from_lookup(self, "VPC", vpc_id=os.environ.get("VPC_ID"))
        subnet_list = []
        for subnet in os.environ.get("SUBNET_IDS").split(","):
            bits = subnet.strip().split(":")
            subnet_id = bits[0]
            subnet_az = bits[1]
            subnet_list.append(ec2.Subnet.from_subnet_attributes(self, subnet_id, subnet_id=subnet_id, availability_zone=subnet_az))


        ### S3
        s3_bucket_name = os.environ.get("S3_BUCKET_NAME", "study-tracker-cdk-s3-bucket-" + stage_name)
        bucket = s3.Bucket(
            self, "StudyTrackerS3Bucket" + stage_name,
            bucket_name=s3_bucket_name,
            versioned=True,
            removal_policy=aws_cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )


        ### RDS
        rds_instance_name = "study-tracker-rds-instance-" + stage_name
        rds_db_name = "StudyTrackerRDSDatabase" + stage_name
        postgressql_version = rds.PostgresEngineVersion.VER_13_6
        db_instance_type = ec2.InstanceType(os.environ.get("RDS_INSTANCE_TYPE", "t3.small"))

        rds_security_group = ec2.SecurityGroup(self, "PostgresDatabaseSecurityGroup", vpc=vpc, allow_all_outbound=True)
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(5432))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(5432))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443))

        rds_database = rds.DatabaseInstance(
            self,
            "StudyTrackerRDSInstance" + stage_name,
            database_name=rds_db_name,
            instance_identifier=rds_instance_name,
            engine=rds.DatabaseInstanceEngine.postgres(version=postgressql_version),
            instance_type=db_instance_type,
            vpc_subnets=ec2.SubnetSelection(subnets=subnet_list),
            security_groups=[rds_security_group],
            vpc=vpc,
            port=5432,
            credentials=rds.Credentials.from_secret(db_root_secret),
            removal_policy=aws_cdk.RemovalPolicy.DESTROY,
            # deletion_protection=production_mode,
            multi_az=False,  # true for redundancy
            storage_type=rds.StorageType.GP2,  # io1 for high performance
            allocated_storage=50,
            backup_retention=Duration.days(10)
        )


        ### ElasticSearch
        es_version = es.EngineVersion.ELASTICSEARCH_7_10
        es_name = "st-search-" + stage_name

        es_security_group = ec2.SecurityGroup(self, "ElasticSearchSecurityGroup", vpc=vpc, allow_all_outbound=True)
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(9200))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(9200))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(80))

        es_domain = es.Domain(
            self,
            "StudyTrackerElasticSearch" + stage_name,
            domain_name=es_name,
            vpc=vpc,
            vpc_subnets=[ec2.SubnetSelection(subnets=[subnet_list[0]])],
            security_groups=[es_security_group],
            version=es_version,
            capacity=es.CapacityConfig(
                master_nodes=0,
                data_nodes=1,
                data_node_instance_type=os.environ.get("ES_INSTANCE_TYPE", "t3.small.search")
            ),
            ebs=es.EbsOptions(volume_size=20),
            fine_grained_access_control=es.AdvancedSecurityOptions(
                master_user_name="studytracker",
                master_user_password=elasticsearch_secret.secret_value
            ),
            node_to_node_encryption=True,
            enforce_https=True,
            encryption_at_rest=es.EncryptionAtRestOptions(enabled=True),
            removal_policy=aws_cdk.RemovalPolicy.DESTROY
        )
        es_domain.add_access_policies(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],
            actions=["es:*"],
            resources=[es_domain.domain_arn, es_domain.domain_arn + "/*"]
        ))


        ### EventBridge

        event_bus_name = "study-tracker-event-bus-" + stage_name
        event_bus = events.EventBus(self, "StudyTrackerEventBridge" + stage_name,
                                    event_bus_name=event_bus_name)


        ### EC2

        # Instance type
        ec2_instance_type = ec2.InstanceType(os.environ.get("EC2_INSTANCE_TYPE", "t2.medium"))

        # AMI
        ec2_ami_user_data = ec2.UserData.for_linux()
        ec2_ami_user_data.add_commands(
            'exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1',  # Redirects script output to logs and console
            'apt-get update -y',
            'apt-get install -y git awscli ec2-instance-connect',
            'until git clone https://github.com/aws-quickstart/quickstart-linux-utilities.git; do echo "Retrying"; done',
            'cd /quickstart-linux-utilities',
            'source quickstart-cfn-tools.source',
            'qs_update-os || qs_err',
            'qs_bootstrap_pip || qs_err',
            'qs_aws-cfn-bootstrap || qs_err',
            'mkdir -p /opt/aws/bin',
            'ln -s /usr/local/bin/cfn-* /opt/aws/bin/'
        )
        ec2_machine_image = ec2.MachineImage.from_ssm_parameter(
            '/aws/service/canonical/ubuntu/server/focal/stable/current/amd64/hvm/ebs-gp2/ami-id',
            os=ec2.OperatingSystemType.LINUX,
            user_data=ec2_ami_user_data
        )

        # Security group
        ec2_security_group = ec2.SecurityGroup(
            self,
            "study-tracker-ec2-security-group-" + stage_name,
            vpc=vpc,
            allow_all_outbound=True
        )
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(80))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(8080))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(8080))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(8443))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(8443))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))
        ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(22))

        # Instance
        # Set environment parameters
        ec2_instance_user_data = ec2.UserData.for_linux()
        ec2_instance_user_data.add_commands("export APPLICATION_SECRET_NAME=" + application_secret.secret_name)
        ec2_instance_user_data.add_commands("export SSL_SECRET_NAME=" + ssl_secret.secret_name)
        ec2_instance_user_data.add_commands("export SAML_SECRET_NAME=" + saml_secret.secret_name)
        ec2_instance_user_data.add_commands("export DB_ROOT_SECRET_NAME=" + db_root_secret.secret_name)
        ec2_instance_user_data.add_commands("export DB_USER_SECRET_NAME=" + db_user_secret.secret_name)
        ec2_instance_user_data.add_commands("export ELASTICSEARCH_SECRET_NAME=" + elasticsearch_secret.secret_name)

        ec2_instance_user_data.add_commands("export ST_ADMIN_EMAIL=" + os.environ.get("ADMIN_EMAIL"))
        ec2_instance_user_data.add_commands("export ST_ADMIN_PASSWORD=" + os.environ.get("ADMIN_PASSWORD"))
        ec2_instance_user_data.add_commands("export ST_VERSION=" + os.environ.get("ST_VERSION"))
        ec2_instance_user_data.add_commands("export JDK_VERSION=" + os.environ.get("JDK_VERSION", "11"))

        ec2_instance_user_data.add_commands("export DB_INSTANCE_NAME=" + rds_instance_name)
        ec2_instance_user_data.add_commands("export DB_PORT=" + str(rds_database.instance_endpoint.port))

        ec2_instance_user_data.add_commands("export ELASTICSEARCH_INSTANCE_NAME=" + es_name)
        ec2_instance_user_data.add_commands("export ELASTICSEARCH_PORT=443")

        ec2_instance_user_data.add_commands("export EVENTBRIDGE_BUS_NAME=" + event_bus_name)

        ec2_instance_user_data.add_commands("export S3_BUCKET_NAME=" + s3_bucket_name)

        ec2_instance_user_data.add_commands("export EGNYTE_TENANT_NAME=" + os.environ.get("EGNYTE_TENANT_NAME"))
        ec2_instance_user_data.add_commands("export EGNYTE_API_TOKEN=" + os.environ.get("EGNYTE_API_TOKEN"))
        ec2_instance_user_data.add_commands("export EGNYTE_ROOT_FOLDER=" + os.environ.get("EGNYTE_ROOT_FOLDER"))

        ec2_instance_user_data.add_commands("export BENCHLING_TENANT_NAME=" + os.environ.get("BENCHLING_TENANT_NAME"))
        ec2_instance_user_data.add_commands("export BENCHLING_CLIENT_ID=" + os.environ.get("BENCHLING_CLIENT_ID"))
        ec2_instance_user_data.add_commands("export BENCHLING_CLIENT_SECRET=" + os.environ.get("BENCHLING_CLIENT_SECRET"))

        ec2_instance_user_data.add_commands("export SMTP_HOST=" + os.environ.get("SMTP_HOST"))
        ec2_instance_user_data.add_commands("export SMTP_PORT=" + os.environ.get("SMTP_PORT"))
        ec2_instance_user_data.add_commands("export SMTP_USER=" + os.environ.get("SMTP_USER"))
        ec2_instance_user_data.add_commands("export SMTP_PASSWORD=" + os.environ.get("SMTP_PASSWORD"))

        ec2_instance_user_data.add_commands("export AWS_REGION=" + aws_cdk.Stack.of(self).region)

        # Add the startup script
        startup_script_file = os.path.join(os.path.split(os.path.realpath(__file__))[0],
                                           "install-from-source.sh")
        with open(startup_script_file) as infile:
            for line in infile:
                # if line.strip() != "" and not line.startswith("#"):
                ec2_instance_user_data.add_commands(line.strip())

        ec2_instance_name = "study-tracker-ec2-instance-" + stage_name
        ec2_server = ec2.Instance(
            self,
            "StudyTrackerEC2Instance" + stage_name,
            instance_name=ec2_instance_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=subnet_list),
            machine_image=ec2_machine_image,
            security_group=ec2_security_group,
            instance_type=ec2_instance_type,
            key_name=os.environ.get("EC2_SSH_KEY_NAME"),
            user_data=ec2_instance_user_data,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(100, volume_type=ec2.EbsDeviceVolumeType.GP2)
                )
            ]

        )
        ec2_server.apply_removal_policy(aws_cdk.RemovalPolicy.DESTROY)
        ec2_server.role.attach_inline_policy(iam.Policy(
            self,
            "StudyTrackerEC2InstanceInlinePolicy" + stage_name,
            policy_name="study-tracker-ec2-instance-inline-policy-" + stage_name,
            statements=[
                iam.PolicyStatement(
                    actions=["rds:DescribeDBInstances", "es:DescribeElasticsearchDomain"],
                    resources=["*"]
                )
            ]
        ))

        # Add user-defined security groups
        for security_group_id in os.environ.get("EC2_SECURITY_GROUP_IDS", "").split(","):
            security_group = ec2.SecurityGroup.from_security_group_id(self, "SG", security_group_id, mutable=False)
            ec2_server.add_security_group(security_group)


        # Permissions
        event_bus.grant_put_events_to(ec2_server)
        bucket.grant_read_write(ec2_server)
        es_domain.grant_read_write(ec2_server)
        db_root_secret.grant_read(ec2_server)
        db_user_secret.grant_read(ec2_server)
        elasticsearch_secret.grant_read(ec2_server)
        ssl_secret.grant_read(ec2_server)
        saml_secret.grant_read(ec2_server)
        application_secret.grant_read(ec2_server)

        ### Print output
        CfnOutput(self, "EC2-private-IP", value=ec2_server.instance_private_ip)
        CfnOutput(self, "Database-Host", value=rds_database.instance_endpoint.hostname)
        CfnOutput(self, "ElasticSearch-Host", value=es_domain.domain_endpoint)
