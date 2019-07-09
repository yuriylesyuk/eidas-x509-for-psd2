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
# curl --fail -H 'SSL_CLIENT_CERT: -----BEGIN CERTIFICATE-----\nMIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\nREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\nDAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\nQ0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\nMTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l\nMQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w\nDQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz\nNDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygUI6R+8LEMgB\n4mVPKCq9a7AW1UuTXSXb4/GehFi+fWmcaUCUqrLamPUZKEelW2LZ92dSb/uFKA56\nYpI0kEcEwjE0DUl/7oZsdPKeSxPfixOpuj9m3V3VZIDbYxgKjnaxWHkobXCIzhHp\n7AQ6cMpPY7i4O+IXK4bY4cqImW/jBiHhV1tkAHCrRyQgb9aRDFN1CqyUdL9XBzC7\noO/GdVlfJPX8YlQz9Dd9PrXL0ORsvms2wRArVFgiDIPNcgJKGIOigHTzb66WIutu\nmBYrMcObXf+9Mb7q2KUeRFizKlO7t9H3vDmKi+nYJLNXDbJLf6+kRJj5EfMOP/MG\nXGluValZAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG\nBwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG\nUFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG\n9w0BAQsFAAOCAQEAesGPHrsobCiPqA49tYzDpgWFm33C+9bTqisRd07bCjWWKLpw\nZsQjxZqTUVSaHedXjxF92JdWgcTtW2jhjYIiEixfaUkoEgpqPfPhDTuqpdw2dD2z\n/N0bdVuxIhxatwA/4Dh0zMO0e3GTmK0iMcRczaPuiCQiDuEaoKy+ZpDzdGfrsmDx\n5wKhIdJ/HoV/fi3gjnUcBUFI3n9MZxinPfIvbouHkRpBtyN8T25NGdpKgLX5P3l9\nyE+a+3BoVXBsDgmkuf5pkcagyWC53vZRwceBKEaRzVELmL+/9ftRm6d/DT54tCiR\nQ1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\n-----END CERTIFICATE-----' http://$ORG-$ENV.apigee.net/eidas-parse-certificate/show






# curl --fail -H 'REQUEST-PEM: -----BEGIN CERTIFICATE REQUEST-----\nMIIDJDCCAgwCAQAwejERMA8GA1UEYQwIMTIzNDU5ODcxEjAQBgNVBAcMCU51cmVtYmVyZzEPMA0GA1UECAwGQmF5ZXJuMRAwDgYDVQQGEwdHZXJtYW55MQswCQYDVQQLDAJvdTEMMAoGA1UECgwDb3JnMRMwEQYDVQQDDApkb21haW5OYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlfTKcv2bmQ8J7bJoD3rgoYMWSbhtgmd4X876ThUiY2FO2fDaGYVC2mF6/DSHTtayAQpa0mipIK56UfAqdOVqgWDDylOOLs/nf+R0J3ccmSibhC+949v5SI2/iuw0VQhvswi+P5ZKv9nhfl4Gyp7l+8zKtl0NSHOEPfpV/KxI3ZOQ9srpi1joiX9/R8u/1T4L9QTFIq62GoBcF2pPBrQK5k2nRnMReahivMznNIAQK4bqdKfJAhjrXM3hYoPILe5uV6f46eNJMsTRIucJ2iQorwwVIxVCKx6Fklb1jb3QfuFdlbM/nImZIuTGQXskYrMiqaom5aXm3p0ovOAJ3HT0twIDAQABoGUwYwYJKoZIhvcNAQkOMVYwVDBSBggrBgEFBQcBAwRGMEQwQgYGBACBmCcCMDgwJjARBgcEAIGYJwEBDAZQU1BfQVMwEQYHBACBmCcBAgwGUFNQX1BJDAduY2FuYW1lDAVuY2FpZDANBgkqhkiG9w0BAQsFAAOCAQEADty06i9b5zrqa/MCiT//uRrklX02RnpQgQAdYqVEzGJH2rqT0cJ6KUtYjO8J60SC4yTiV1+p8lSxUHvS146VU8uEEZO486pGajj6zsdwQDs+uK50uvigNaGTO9Hu5me7F+x2BqDsMlpizJqmqI2W67Sq5MsIaVfF031MOVujtC9e/J4n2Hb66lCHat8mRD4bvQqdp07XHpqRDJaFQiz9XIMfjooafhPLtX4e8OZP+hm7SjILz5ksrW7vqaRcUa8SJCAqHnezY900NOj7hxNYP71I8aZuE56p6iPPQQhrDSIhLvnnrrAhW/UkX1i6j2qbLEt79R4Wr/KKUsBlWHksDQ==\n-----END CERTIFICATE REQUEST-----' -d '{  "certInfo": {    "basicConstraints": "CA: true",    "subject": "emailAddress\u003dca@test.de, CN\u003dAuthority CA Domain Name, OU\u003dIT, O\u003dAuthority CA, L\u003dFrankfurt, ST\u003dHessen, C\u003dDE, OID.2.5.4.97\u003dPSDES-BDE-3DFD21",    "issuer": "C\u003dUK, L\u003dLondon, O\u003dExco PLC, OU\u003dCA Services/Interm Desk, CN\u003dExco-Interm-CA",    "validFrom": 1543573407000,    "expiryDate": 1559740306000,    "isValid": "\u003cTODO\u003e",    "publicKey": "RSA, 2048",    "serialNumber": "6fc2947a",    "sigAlgName": "SHA1withRSA",    "version": 3,    "fingerprintSha256": "8345ed6b67056bb641e6ccac5a0579acdf80663de59f7b92f561b66bb6d8876b",    "fingerprintSha1": "cc1adb500568facbff32b475161936dc5becfc4b",    "ncaName": "ncaname",    "ncaId": "ncaid",    "rolesOfPSP": ["PSP_AS","PSP_PI"]  }}' http://$ORG-$ENV.apigee.net/eidas-parse-certificate/sign
