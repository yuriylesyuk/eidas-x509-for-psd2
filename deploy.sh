#!/bin/bash
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"



requiredvarsareset=Y
if [ -z ${ORG+x} ]; then
    echo "Environment variable ORG is not set. It should contain the name of your organization."; 
    requiredvarsareset=N
fi
if [ -z ${ENV+x} ]; then
    echo "Environment variable ENV is not set. It should contain the name of your organization's environment."; 
    requiredvarsareset=N
fi
if [ -z ${ORG_ADMIN_USERNAME+x} ]; then
    echo "Environment variable ORG_ADMIN_USERNAME is not set. "; 
    requiredvarsareset=N
fi
if [ -z ${ORG_ADMIN_PASSWORD+x} ]; then
    echo "Environment variable ORG_ADMIN_PASSWORD is not set. "; 
    requiredvarsareset=N
fi
if [ "$requiredvarsareset" = "N" ]; then
    exit 1
fi


set -eu

cd $BASEDIR

apigeetool deployproxy -u "$ORG_ADMIN_USERNAME" -p "$ORG_ADMIN_PASSWORD" -o "$ORG" -e "$ENV" -n eidas-parse-certificate -d ./eidas-certificate-bundle

