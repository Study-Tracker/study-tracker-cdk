import aws_cdk
from aws_cdk import (
    Stack,
    SecretValue,
    Duration,
    CfnOutput,
    aws_events as events,
    aws_s3 as s3,
    aws_iam as iam,
    aws_rds as rds,
    aws_ec2 as ec2,
    aws_opensearchservice as es
)
from constructs import Construct
import os
from cdk_templates.secrets_stack import SecretUtils
import cdk_templates.secrets_stack as secrets_stack


class StudyTrackerCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, secret_utils: SecretUtils, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stage_name = os.environ.get("ST_ENV")
        production_mode = bool(os.environ.get("PRODUCTION_MODE", "False"))

        ### Secrets
        db_root_secret = secret_utils.get_secret_json(secrets_stack.db_root_secret_name + stage_name)
        db_user_secret = secret_utils.get_secret_json(secrets_stack.db_user_secret_name + stage_name)
        es_secret = secret_utils.get_secret_json(secrets_stack.elasticsearch_secret_name + stage_name)
        saml_secret = secret_utils.get_secret_string(secrets_stack.saml_secret_name + stage_name)
        ssl_secret = secret_utils.get_secret_string(secrets_stack.ssl_secret_name + stage_name)
        application_secret = secret_utils.get_secret_string(secrets_stack.application_secret_name + stage_name)

        ### VPC
        vpc = ec2.Vpc.from_lookup(self, "VPC", vpc_id=os.environ.get("VPC_ID"))
        subnet_list = []
        for subnet in os.environ.get("SUBNET_IDS").split(","):
            bits = subnet.strip().split(":")
            subnet_id = bits[0]
            subnet_az = bits[1]
            subnet_list.append(ec2.Subnet.from_subnet_attributes(self, subnet_id, subnet_id=subnet_id, availability_zone=subnet_az))

        ### S3
        bucket = s3.Bucket(
            self,
            "study-tracker-cdk-s3-bucket-" + stage_name,
            versioned=True,
            removal_policy=aws_cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        ### RDS
        postgressql_version = rds.PostgresEngineVersion.VER_13_6
        db_instance_type = ec2.InstanceType(os.environ.get("RDS_INSTANCE_TYPE", "t3.small"))

        rds_security_group = ec2.SecurityGroup(self, "PostgresDatabaseSecurityGroup", vpc=vpc, allow_all_outbound=True)
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(5432))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(5432))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))
        rds_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443))

        database = rds.DatabaseInstance(
            self,
            "study-tracker-cdk-rds-instance-" + stage_name,
            database_name="StudyTrackerCdkRdsDatabase" + stage_name,
            instance_identifier="study-tracker-cdk-rds-postgres-" + stage_name,
            engine=rds.DatabaseInstanceEngine.postgres(version=postgressql_version),
            instance_type=db_instance_type,
            vpc_subnets=ec2.SubnetSelection(subnets=subnet_list),
            security_groups=[rds_security_group],
            vpc=vpc,
            port=5432,
            credentials=rds.Credentials.from_password(
                username=db_root_secret["username"],
                password=SecretValue(db_root_secret["password"])
            ),
            removal_policy=aws_cdk.RemovalPolicy.DESTROY,
            deletion_protection=production_mode,
            multi_az=False,  # true for redundancy
            storage_type=rds.StorageType.GP2,  # io1 for high performance
            allocated_storage=50,
            backup_retention=Duration.days(10)
        )

        ### ElasticSearch
        es_version = es.EngineVersion.ELASTICSEARCH_7_10
        es_name = "study-tracker-search" if production_mode else "study-tracker-search-dev"

        es_security_group = ec2.SecurityGroup(self, "ElasticSearchSecurityGroup", vpc=vpc, allow_all_outbound=True)
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(9200))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(9200))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(443))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
        es_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.tcp(80))

        es_domain = es.Domain(
            self,
            "study-tracker-elasticsearch-domain-" + stage_name,
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
                master_user_name=es_secret["username"],
                master_user_password=SecretValue(es_secret["password"])
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

        event_bus = events.EventBus(self, "study-tracker-event-bus-" + stage_name,
                                    event_bus_name="study-tracker-events")


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
        # ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.all_traffic())
        # ec2_security_group.add_ingress_rule(ec2.Peer.any_ipv6(), ec2.Port.all_traffic())

        # Instance
        # Set environment parameters
        ec2_instance_user_data = ec2.UserData.for_linux()
        ec2_instance_user_data.add_commands("export ST_APP_SECRET=" + application_secret)
        ec2_instance_user_data.add_commands("export ST_ADMIN_EMAIL=" + os.environ.get("ADMIN_EMAIL"))
        ec2_instance_user_data.add_commands("export ST_ADMIN_PASSWORD=" + os.environ.get("ADMIN_PASSWORD"))
        ec2_instance_user_data.add_commands("export ST_VERSION=" + os.environ.get("ST_VERSION"))
        ec2_instance_user_data.add_commands("export JDK_VERSION=" + os.environ.get("JDK_VERSION", "11"))

        ec2_instance_user_data.add_commands("export DB_HOST=" + database.instance_endpoint.hostname)
        ec2_instance_user_data.add_commands("export DB_PORT=" + str(database.instance_endpoint.port))
        ec2_instance_user_data.add_commands("export DB_ROOT_USER=" + db_root_secret["username"])
        ec2_instance_user_data.add_commands("export DB_ROOT_PASSWORD=" + db_root_secret["password"])
        ec2_instance_user_data.add_commands("export DB_PASSWORD=" + db_user_secret["password"])

        ec2_instance_user_data.add_commands("export ELASTICSEARCH_HOST=" + es_domain.domain_endpoint)
        ec2_instance_user_data.add_commands("export ELASTICSEARCH_PORT=443")
        ec2_instance_user_data.add_commands("export ELASTICSEARCH_USERNAME=" + es_secret["username"])
        ec2_instance_user_data.add_commands("export ELASTICSEARCH_PASSWORD=" + es_secret["password"])

        ec2_instance_user_data.add_commands("export SSL_KEYSTORE_PASSWORD=" + ssl_secret)
        ec2_instance_user_data.add_commands("export SAML_KEYSTORE_PASSWORD=" + saml_secret)

        ec2_instance_user_data.add_commands("export EGNYTE_TENANT=" + os.environ.get("EGNYTE_TENANT_NAME"))
        ec2_instance_user_data.add_commands("export EGNYTE_API_TOKEN=" + os.environ.get("EGNYTE_API_TOKEN"))
        ec2_instance_user_data.add_commands("export EGNYTE_ROOT_FOLDER=" + os.environ.get("EGNYTE_ROOT_FOLDER"))

        ec2_instance_user_data.add_commands("export BENCHLING_TENANT=" + os.environ.get("BENCHLING_TENANT_NAME"))

        ec2_instance_user_data.add_commands("export AWS_REGION=" + aws_cdk.Stack.of(self).region)

        # Add the startup script
        startup_script_file = os.path.join(os.path.split(os.path.realpath(__file__))[0],
                                           "install-from-source.sh")
        with open(startup_script_file) as infile:
            for line in infile:
                if line.strip() != "" and not line.startswith("#"):
                    ec2_instance_user_data.add_commands(line.strip())
        ec2_server = ec2.Instance(
            self,
            "study-tracker-ec2-instance-" + stage_name,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=subnet_list),
            machine_image=ec2_machine_image,
            security_group=ec2_security_group,
            instance_type=ec2_instance_type,
            key_name=os.environ.get("EC2_SSH_KEY_NAME"),
            user_data=ec2_instance_user_data
        )
        ec2_server.apply_removal_policy(aws_cdk.RemovalPolicy.DESTROY)

        # Permissions
        event_bus.grant_put_events_to(ec2_server)
        bucket.grant_read_write(ec2_server)
        es_domain.grant_read_write(ec2_server)

        # Update secret values
        secret_utils.update_secret(secrets_stack.db_root_secret_name + stage_name, database.instance_endpoint.hostname, "host")
        secret_utils.update_secret(secrets_stack.db_user_secret_name + stage_name, database.instance_endpoint.hostname, "host")
        secret_utils.update_secret(secrets_stack.elasticsearch_secret_name + stage_name, es_domain.domain_endpoint, "host")

        ### Print output
        CfnOutput(self, "EC2-private-IP", value=ec2_server.instance_private_ip)
        CfnOutput(self, "Database-Host", value=database.instance_endpoint.hostname)
        CfnOutput(self, "ElasticSearch-Host", value=es_domain.domain_endpoint)
