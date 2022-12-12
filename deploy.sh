#!/bin/bash

set -e -x

# Parse input arguments
export PRODUCTION_MODE=false
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--production)
      export PRODUCTION_MODE=true
      shift
      ;;
    -h|--help)
      echo "Usage: deploy.sh [options] <profile>"
      echo "  -p, --production      Run deployment in production mode"
      echo "  -h, --help            Print this help message"
      exit 0
      ;;
    *)
      export ST_ENV="$1"
      break
      ;;
  esac
done

if [[ -z "$ST_ENV" ]]; then
  echo "Usage: deploy.sh [options] <profile>"
  echo "  -p, --production      Run deployment in production mode"
  echo "  -h, --help            Print this help message"
  exit 1
fi

echo "Deploying Study Tracker to environment $ST_ENV"

# Test that environment file exists
if [ ! -f "configs/$ST_ENV.env" ]; then
    echo "Environment file configs/$ST_ENV.env does not exist"
    exit 1
fi

# Load the environment variables
source configs/default_variables.sh
if [ "$PRODUCTION_MODE" = true ]; then
    echo "Running in production mode"
    source configs/production_defaults.sh
else
    echo "Running in development mode"
    source configs/development_defaults.sh
fi
source configs/${ST_ENV}.env

# Run the CDK scripts
cdk deploy --app "python app.py" --all --require-approval never
#cdk deploy --app "python secrets_app.py" --all --require-approval never
#cdk deploy --app "python study_tracker_app.py" --all --require-approval never