# Study Tracker CDK

This is an AWS CDK package for deploying Study Tracker with all required services configured via CloudFormation. This 
includes:

- EC2 instance for running the Study Tracker web application
- PostgreSQL database in RDS
- ElasticSearch single-node cluster for power search
- EventBridge bus for publishing application events
- An S3 bucket for application storage

A few things this script will *not* provision for you, which you should create ahead of time:

- A VPC and subnets for hosting the application and databases
- An EC2 SSH keypair for connecting to your instance
- An email server and account that supports SMTP
- An Egnyte tenant with a registered API application and key
- A Benchling tenant with registered App and credentials

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
   
   By default, the stack will be deployed in 'development' mode. This will utilize smaller/cheaper instance types and disable some protections. To deploy the stack in 'production' mode using an environment file named `production.env`, run:

   ```bash
   sh deploy.sh -p production
   ```


## CDK Docs

The `cdk.json` file tells the CDK Toolkit how to execute your app.

This project is set up like a standard Python project.  The initialization
process also creates a virtualenv within this project, stored under the `.venv`
directory.  To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .venv
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .venv/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .venv\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

Install AWS CDK if you do not already have it available.

```bash
npm install -g aws-cdk
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

To deploy the stack to the current default AWS environment for your CLI, use the following command:

```bash
cdk deploy StudyTrackerCdkStack --parameters AdminEmail=admin@host.com --parameters AdminPassword=mypassword
```

Once the stack deployment completes, you can SSH to the created EC2 server and check that the application installation completed successfully. Logs will be outputted to `/var/log/cloud-init-output.log`

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

Enjoy!
