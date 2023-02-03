# Study Tracker CDK

This is an AWS CDK package for deploying Study Tracker with all required services configured via CloudFormation. This 
includes:

- EC2 instance for running the Study Tracker web application.
- PostgreSQL database in RDS.
- ElasticSearch single-node cluster for power search.
- EventBridge bus for publishing application events.
- An S3 bucket for application storage.

A few things this script will *not* provision for you, which you should create ahead of time:

- A VPC and subnets for hosting the application and databases. It is recommended to use private subnets for your application and databases, and public subnets for a load balancer (not provided) if you plan on making your instance accessible to the public internet. 
- An EC2 SSH keypair for connecting to your instance.
- An email server and account that supports SMTP.
- An Egnyte tenant with a registered API application and key.
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