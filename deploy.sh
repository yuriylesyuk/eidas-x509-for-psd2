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

echo "Quick test by running an example transaction..."
curl --fail -H 'SSL_CLIENT_CERT: -----BEGIN CERTIFICATE-----\nMIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\nREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\nDAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\nQ0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\nMTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l\nMQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w\nDQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz\nNDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygUI6R+8LEMgB\n4mVPKCq9a7AW1UuTXSXb4/GehFi+fWmcaUCUqrLamPUZKEelW2LZ92dSb/uFKA56\nYpI0kEcEwjE0DUl/7oZsdPKeSxPfixOpuj9m3V3VZIDbYxgKjnaxWHkobXCIzhHp\n7AQ6cMpPY7i4O+IXK4bY4cqImW/jBiHhV1tkAHCrRyQgb9aRDFN1CqyUdL9XBzC7\noO/GdVlfJPX8YlQz9Dd9PrXL0ORsvms2wRArVFgiDIPNcgJKGIOigHTzb66WIutu\nmBYrMcObXf+9Mb7q2KUeRFizKlO7t9H3vDmKi+nYJLNXDbJLf6+kRJj5EfMOP/MG\nXGluValZAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG\nBwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG\nUFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG\n9w0BAQsFAAOCAQEAesGPHrsobCiPqA49tYzDpgWFm33C+9bTqisRd07bCjWWKLpw\nZsQjxZqTUVSaHedXjxF92JdWgcTtW2jhjYIiEixfaUkoEgpqPfPhDTuqpdw2dD2z\n/N0bdVuxIhxatwA/4Dh0zMO0e3GTmK0iMcRczaPuiCQiDuEaoKy+ZpDzdGfrsmDx\n5wKhIdJ/HoV/fi3gjnUcBUFI3n9MZxinPfIvbouHkRpBtyN8T25NGdpKgLX5P3l9\nyE+a+3BoVXBsDgmkuf5pkcagyWC53vZRwceBKEaRzVELmL+/9ftRm6d/DT54tCiR\nQ1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\n-----END CERTIFICATE-----' http://$ORG-$ENV.apigee.net/eidas-parse-certificate
