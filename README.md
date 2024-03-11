# Study Tracker CDK

This is an AWS CDK package for deploying Study Tracker with all required services configured via CloudFormation. This 
includes:

- EC2 instance for running the Study Tracker web application.
- PostgreSQL database in RDS.
- ElasticSearch single-node cluster for power search.
- EventBridge bus for publishing application events.
- An S3 bucket for application storage.
- SecretsManager records for all generated credentials.

A few things this script will *not* provision for you, which you should create ahead of time:

- A VPC and subnets for hosting the application and databases. It is recommended to use private subnets for your application and databases, and public subnets for a load balancer (not provided) if you plan on making your instance accessible to the public internet. 
- An EC2 SSH keypair for connecting to your instance.
- An email server and account that supports SMTP.
- A Benchling tenant with registered App and credentials.

## Deploying the stack

Be sure that you have the AWS CLI installed and configured with credentials that have permissions 
to deploy CloudFormation, and that the AWS CDK is installed, as well. Instructions can be found
below. 

1. Create or modify an existing configuration `.env` file in the `configs` directory. These files define AWS environment and Study Tracker configuration parameters that will be used to deploy the application. The name of the file will be used when running the deployment to reference the environment. An example file, `example_environment`, has been provided as a template for creating your own `.env` files.
2. Create and/or activate the Python virtual environment for the project & install dependencies:

    ```bash
   virtualenv -p python3 venv
   source venv/bin/activate
   ./venv/bin/python -m pip install -r requirements.txt
    ```
3. Deploy the stack with the `deploy.sh` script, passing the environment reference as a single argument. For example, build Study Tracker with the configuration defined in `development.env`, run the command:

    ```bash
   sh deploy.sh development
    ```
   
   By default, the stack will be deployed in 'development' mode. This will utilize smaller/cheaper instance types and disable some protections. To deploy the stack in 'production' mode using an environment file named `production.env`, run the script with the `-p` flag:

   ```bash
   sh deploy.sh -p production
   ```
   
**Note:** The name of the environment file is not important, but the name of the environment itself is. The environment name is used to create the name of the stack, and must be unique across all AWS accounts. For example, if you have a `development.env` file and a `production.env` file, you can deploy the stack in development mode with the command `sh deploy.sh development`, and in production mode with the command `sh deploy.sh -p production`.

## After deployment

It takes roughly 15 minutes for the stack to deploy, after which it will take another 10 minutes or so for the EC2 instance to boot and the application to be installed. The CDK script will print the private IP address of the EC2 instance, as well as host names of the RDS and OpensearchService instances, like so:

```bash
Outputs:
study-tracker-application-stack-development.DatabaseHost = study-tracker-rds-postgres-development.xxxxxxxx.us-east-1.rds.amazonaws.com
study-tracker-application-stack-development.EC2privateIP = 11.22.222.222
study-tracker-application-stack-development.ElasticSearchHost = vpc-study-tracker-search-xxxxxxxx.us-east-1.es.amazonaws.com
```

Assuming you have VPN access to your VPC, you can connect to the EC2 instance via SSH using the private IP address and the keypair you specified in the `.env` file. 

```bash
ssh -i ~/.ssh/my-keypair.pem ubuntu@11.22.222.222
```

Once connected, you can run the following commands to check the status of the application:

```bash
sudo systemctl status study-tracker
more /var/log/cloud-init-output.log
more /opt/study-tracker/logs/study-tracker.log
```

If everything launched correctly, you should be able to reach your Study Tracker instance at the public IP address of the EC2 instance. If you are using a load balancer, you can reach the instance at the DNS name of the load balancer.

## Profile Configuration File Reference

The following is an example configuration file you can use for reference, with brief explanation of each field:

```bash
#!/usr/bin/env bash

### Study Tracker dependencies

# Version of Study Tracker you would like to deploy. This can be a specific version number, or 
# 'latest' to deploy the latest version of the `main` branch.
export ST_VERSION="v0.9.6"
#export ST_VERSION="latest"


### Study Tracker user configuration

# The email address of the Study Tracker admin user. This user will be created in the database and 
# will be able to log in to the application.
export ADMIN_EMAIL="user@email.com"
export ADMIN_PASSWORD="thisisatest"


### AWS Environment

# The ID of the VPC the stack will be deployed into
export VPC_ID="vpc-1234567890"

# The AWS account number.
export AWS_ACCOUNT_ID="1234567890"

# The region to deploy the stack into.
export AWS_REGION="us-east-1"

# The IDs of two private subnets to deploy the application into. These should be in different 
# availability zones.
export SUBNET_IDS="subnet-1234567890:us-east-1a,subnet-1234567890:us-east-1b"


### EC2

# Name of an existing EC2 SSH keypair to use for connecting to the instance.
export EC2_SSH_KEY_NAME="My_keypair"

# Any additional security groups you would like to attach to the EC2 instance. This should be a 
# comma-separated list of security group IDs. It is a good idea to add your default VPC group here.
export EC2_SECURITY_GROUP_IDS="sg-12345677890"


### Elasticsearch

# Subnet ID for the Elasticsearch instance. This should be a private subnet.
export ES_SUBNET_ID="subnet-1234567890"


### Email

# Connection info for an SMTP server for sending emails.
export SMTP_HOST="smtp.office365.com"
export SMTP_PORT="587"
export SMTP_USER="user@myorg.onmicrosoft.com"
export SMTP_PASSWORD="password"


### Benchling

# The name of your Benchling tenant.
export BENCHLING_TENANT_NAME="myorg"

# The client ID and secret for your Benchling App. These can be found in the Benchling developer 
# console.
export BENCHLING_CLIENT_ID="xxxxxx"
export BENCHLING_CLIENT_SECRET="xxxxxx"
```