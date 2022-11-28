### Installation script for fresh Study Tracker EC2 instance.
### This script build the application from source.

## Parameters

# Predefined
RUN_DIR=/opt/study-tracker
ST_HOST=${ST_PRIVATE_IP}

# User defined
echo "Checking environment properties..."

# App
if [ -z ${ST_VERSION+x} ]; then echo "ST_VERSION must be set with a valid Study Tracker version"; exit; fi
if [ -z ${ST_ADMIN_EMAIL+x} ]; then echo "ST_ADMIN_EMAIL must be set with a valid email"; exit; fi
if [ -z ${ST_ADMIN_PASSWORD+x} ]; then echo "ST_ADMIN_PASSWORD must be set with a valid password"; exit; fi
if [ -z ${ST_APP_SECRET+x} ]; then echo "ST_APP_SECRET must be set with a valid secret"; exit; fi

# AWS
EVENTBRIDGE_BUS_NAME=${EVENTBRIDGE_BUS_NAME}

# Java
if [ -z ${JDK_VERSION+x} ]; then echo "JDK_VERSION must be set with a valid JDK version"; exit; fi

# PostgreSQL database
if [ -z ${DB_HOST+x} ]; then echo "DB_HOST must be set with a valid PostgreSQL host name"; exit; fi
if [ -z ${DB_ROOT_PASSWORD+x} ]; then echo "DB_ROOT_PASSWORD must be set with a valid PostgreSQL root user password"; exit; fi
if [ -z ${DB_PASSWORD+x} ]; then echo "DB_PASSWORD must be set with a valid PostgreSQL database user password"; exit; fi

DB_PORT="${DB_PORT:=5432}"
DB_ROOT_USER="${DB_ROOT_USER:=postgres}"
DB_ROOT_SCHEMA="${DB_ROOT_SCHEMA:=postgres}"
DB_SCHEMA="${DB_SCHEMA:=study-tracker}"
DB_USER="${DB_USER:=studytracker}"

STORAGE_MODE="local"
if [ -z ${EGNYTE_TENANT_NAME+x} ]; then STORAGE_MODE="egnyte"; fi

# SSL
if [ -z ${SSL_KEYSTORE_PASSWORD+x} ]; then echo "SSL_KEYSTORE_PASSWORD must be set with a valid SSL keystore password"; exit; fi
SSL_KEYSTORE_FILENAME="${SSL_KEYSTORE_FILENAME:=stssl.p12}"
SSL_KEYSTORE_ALIAS="${SSL_KEYSTORE_ALIAS:=stsslstore}"

# SAML
if [ -z ${SAML_KEYSTORE_PASSWORD+x} ]; then echo "SAML_KEYSTORE_PASSWORD must be set with a valid SAML keystore password"; exit; fi
SAML_KEYSTORE_FILENAME="${SAML_KEYSTORE_FILENAME:=saml-keystore.jks}"
SAML_KEYSTORE_ALIAS="${SAML_KEYSTORE_ALIAS:=stsaml}"
#SAML_KEYSTORE_PASSWORD=

## Dependency installation
export USER_HOME=/home/${USER:=ubuntu}
cd "${USER_HOME}" || exit
echo "Using home directory: ${USER_HOME}"

echo "Installing core dependencies..."
sudo apt-get update
sudo apt-get install -y "openjdk-${JDK_VERSION}-jdk"
sudo apt-get install -y maven
sudo apt-get install -y git
sudo apt-get install -y postgresql-client
sudo apt-get install -y unzip

curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

echo "Downloading the Study Tracker source code..."
export ST_FOLDER_NAME=study-tracker
export ST_HOME=${USER_HOME}/${ST_FOLDER_NAME}
git clone https://github.com/Study-Tracker/Study-Tracker.git "${ST_HOME}"
cd "${ST_HOME}" || exit
if [ "${ST_VERSION}" != "latest" ]; then
    git checkout tags/"${ST_VERSION}"
fi


## Database setup

echo "Creating database..."

# Create database and user
export PGPASSWORD="${DB_ROOT_PASSWORD}"
psql -h ${DB_HOST} -p ${DB_PORT} -d ${DB_ROOT_SCHEMA} -U ${DB_ROOT_USER} -c "create database \"${DB_SCHEMA}\""
psql -h ${DB_HOST} -p ${DB_PORT} -d ${DB_ROOT_SCHEMA} -U ${DB_ROOT_USER} -c "create user ${DB_USER} with encrypted password '${DB_PASSWORD}'"
psql -h ${DB_HOST} -p ${DB_PORT} -d ${DB_ROOT_SCHEMA} -U ${DB_ROOT_USER} -c "grant all privileges on database \"${DB_SCHEMA}\" to ${DB_USER}"

# Create elasticsearch indexes
curl --location --request PUT "${ELASTICSEARCH_HOST}/studies" --user ${ELASTICSEARCH_USER}:${ELASTICSEARCH_PASSWORD} --basic
curl --location --request PUT "${ELASTICSEARCH_HOST}/assays" --user ${ELASTICSEARCH_USER}:${ELASTICSEARCH_PASSWORD} --basic

## Flyway
cat <<EOF > "${ST_HOME}"/web/flyway.conf
flyway.user=${DB_USER}
flyway.password=${DB_PASSWORD}
flyway.url=jdbc:postgresql://${DB_HOST}:${DB_PORT}/${DB_SCHEMA}
EOF

cd "${ST_HOME}"/web || exit
mvn -Dflyway.configFiles=flyway.conf flyway:clean
mvn -Dflyway.configFiles=flyway.conf flyway:migrate


## Create the run directory
echo "Creating the run directory..."
sudo mkdir ${RUN_DIR}
sudo chown ubuntu:ubuntu ${RUN_DIR}
mkdir ${RUN_DIR}/data
mkdir ${RUN_DIR}/logs

## TLS
# Generate keystore and self-signed certificate
echo "Generating SSL keystore..."
cd "${RUN_DIR}" || exit
keytool -genkeypair -alias ${SSL_KEYSTORE_ALIAS} -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore ${SSL_KEYSTORE_FILENAME} -storepass ${SSL_KEYSTORE_PASSWORD} -keypass ${SSL_KEYSTORE_PASSWORD} -validity 3650 -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown"

## SAML
# Generate a SAML keystore
echo "Generating SAML keystore..."
cd "${RUN_DIR}" || exit
keytool -genkeypair -keyalg RSA -alias ${SAML_KEYSTORE_ALIAS} -keypass ${SAML_KEYSTORE_PASSWORD} -storepass ${SAML_KEYSTORE_PASSWORD} -keystore ${SAML_KEYSTORE_FILENAME} -dname "cn=Unknown, ou=Unknown, o=Unknown, c=Unknown"

## Properties file
cd "${RUN_DIR}" || exit
cat <<EOF > application.properties
### General properties ###

# Required
# Host name of your application (should not include protocol or port). This is used for generating
# links to your application in emails and other notifications.
# Eg. localhost or mywebsite.com

application.host-name=${ST_HOST}

# Required
# Character sequence used for seeding encryption keys. This should ideally be a long, random string
# of characters. It is important that you do not change this value after setting it.

application.secret=${ST_APP_SECRET}


### Admin User ###

# Required
# The first time Study Tracker starts, an admin user will be created. You must specify an email and
# default password for the admin account. The password can be changed after initial startup.

admin.email=${ST_ADMIN_EMAIL}
admin.password=${ST_ADMIN_PASSWORD}


### Data Source ###

# Required
# Provide the connection information for the primary Study Tracker database. The user and schema
# need to be configured ahead of time.

db.username=${DB_USER}
db.password=${DB_PASSWORD}
db.host=${DB_HOST}
db.port=${DB_PORT}
db.name=${DB_SCHEMA}


### AWS ###

# Optional
# If the instance running Study Tracker has an IAM role that assigns it access to EventBridge and
# S3, then these properties can be left blank. Otherwise, provide the region, access key and secret
# key for the account you are running Study Tracker in.

aws.region=${AWS_REGION}
aws.access-key-id=
aws.secret-access-key=

# If you would like to register some S3 buckets for file storage, list them as comma-separated values here.
aws.s3.buckets=


### Events ###

# Determines where to dispatch events. Can be 'eventbridge' or 'local'. Default mode: 'local'

events.mode=eventbridge
aws.eventbridge.bus-name=${EVENTBRIDGE_BUS_NAME}


### Email ###

# Required
# Provide SMTP connection details for outgoing emails.

spring.mail.host=${SMTP_HOST}
spring.mail.port=${SMTP_PORT}
spring.mail.username=${SMTP_USER}
spring.mail.password=${SMTP_PASSWORD}
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
email.outgoing-email-address=\${spring.mail.username}


### Notebook ###

# Connect Study Tracker with your ELN
# Options: 'none', 'benchling'. Default: 'none'

notebook.mode=benchling

# If notebook.mode is set to 'benchling', then you must provide the Benchling API key and the

benchling.tenant-name=${BENCHLING_TENANT_NAME}
benchling.api.client-id=${BENCHLING_CLIENT_ID}
benchling.api.client-secret=${BENCHLING_CLIENT_SECRET}

# Deprecated parameters.
#benchling.api.token=
#benchling.api.username=
#benchling.api.password=
#benchling.api.root-url=
#benchling.api.root-entity=
#benchling.api.root-folder-url=


### File Storage ###

# Options: local, egnyte. Defaults to local

storage.mode=${STORAGE_MODE}

# If storage.use-existing is set to 'true', Study Tracker will use existing folders with the same
# name when trying to create new ones. If set to 'false', Study Tracker throw an error when trying
# to create a folder that already exists. Defaults to 'true'.

storage.use-existing=true

# Sets the maximum recursive read depth for the local file storage. The higher the number, the
# longer it will take to load folder contents and the larger the folder tree that will be returned.

storage.max-folder-read-depth=3

# Local file storage
# Sets the directory used for uploading files.

storage.temp-dir=/tmp

# Sets the folder in which the root program/study/assay storage folder hierarchy will be created.
# Required if storage.mode is set to 'local'.

storage.local-dir=${RUN_DIR}/data


### Egnyte ###

# Required if storage.mode is set to 'egnyte'.

egnyte.tenant-name=${EGNYTE_TENANT_NAME}
egnyte.root-url=https://\${egnyte.tenant-name}.egnyte.com
egnyte.api-token=${EGNYTE_API_TOKEN}

# Sets the folder in which the root program/study/assay storage folder hierarchy will be created.

egnyte.root-path=${EGNYTE_ROOT_FOLDER}

# Sets the maximum number of API requests that will be made to egnyte every second.

egnyte.qps=3


### Search ###

# Study Tracker can integrate with Elasticsearch to provide advanced study search functionality.
# To enable, set search.mode to 'elasticsearch'. The host value should be the full host name
# (without protocol) and the port number. So if my host is https://myelasticdb.com, then the
# value for elasticsearch.host would be 'myelasticdb.com' and the port would be set to 443.

search.mode=elasticsearch
elasticsearch.host=${ELASTICSEARCH_HOST}
elasticsearch.port=${ELASTICSEARCH_PORT}
elasticsearch.username=${ELASTICSEARCH_USERNAME}
elasticsearch.password=${ELASTICSEARCH_PASSWORD}
elasticsearch.use-ssl=true


### Studies ###

# You can change default study code creation behavior here.

study.default-code-prefix=ST
study.default-external-code-prefix=EX
study.study-code-counter-start=101
study.study-code-min-digits=3
study.assay-code-counter-start=1
study.assay-code-min-digits=3


### SSL ###

# Optional
# If SSL is enabled, set the port to 8443 or 443

#server.port=443
#server.ssl.enabled=true
#server.ssl.key-store-type=PKCS12
#server.ssl.key-alias=${SSL_KEYSTORE_ALIAS}
#server.ssl.key-store=${RUN_DIR}/${SSL_KEYSTORE_FILENAME}
#server.ssl.key-store-password=${SSL_KEYSTORE_PASSWORD}

## Okta
#sso.url=${OKTA_SSO_URL}
#security.sso=okta-saml
#saml.audience=${OKTA_AUDIENCE_URL}
#saml.idp=${OKTA_IDP_URL}
#saml.metadata-url=${OKTA_METADATA_URL}
#saml.keystore.location=file:${RUN_DIR}/${SAML_KEYSTORE_FILENAME}
#saml.keystore.alias=${SAML_KEYSTORE_ALIAS}
#saml.keystore.password=${SAML_KEYSTORE_PASSWORD}
EOF


## Build the application
echo "Building application..."
cd "${ST_HOME}" || exit
mvn clean package -DskipTests
cp ${ST_HOME}/web/target/*.war ${RUN_DIR}/study-tracker.war


## Run Study Tracker as a service
echo "Configuring service..."
cat <<EOF > ${ST_HOME}/study-tracker.service
[Unit]
Description=Study Tracker

[Service]
WorkingDirectory=${RUN_DIR}
ExecStart=/usr/bin/java -jar study-tracker.war
Restart=always
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=study-tracker

[Install]
WantedBy=multi-user.target
EOF
sudo mv ${ST_HOME}/study-tracker.service /etc/systemd/system/study-tracker.service

echo "Starting Study Tracker..."
sudo systemctl start study-tracker
sudo systemctl enable study-tracker

echo "Done! Study Tracker is now running." 
