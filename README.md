# Edge Java Callout: eiDAS/PSD2 Certificate Parser

The proxy bundle is ready for deployment. You don't need to compile it in order to use it.

## Quickstart: Building and deploying


apigeetool is a Node.js module and you can install it using npm:

```
npm install -g apigeetool
```

To deploy, set up the following environment variables and execute the deploy.sh script.


```
export ORG=<name-of-edge-org>
export ENV=<name-of-org's-env>
export ORG_ADMIN_USERNAME=<your-username>
export ORG_ADMIN_PASSWORD=<your-password>


./deploy.sh
```

## Configuration

Configure the policy like this:

```
<JavaCallout name="JavaCallout.EiDAS-CertificateParse">
    <Properties>
        <Property name="pem-certificate">request.header.SSL_CLIENT_CERT</Property>
        <Property name="certificate-info">flow.certinfo</Property>
    </Properties>
    <ClassName>com.exco.eidas.EiDASCertificateParserCallout</ClassName>
    <ResourceURL>java://eidas-certificate-parser-1.0.0.jar</ResourceURL>
</JavaCallout>
```

Within the Properties, you can specify the input and output for the eiDAS callout.

| name             | required | meaning                                 |
| ---------------- | -------- | ----------------------------------------|
| pem-certificate  | required | name of context variable that contains certificate in pem format |
| certificate-info | required | name of the context variable that will contain certificate information |

If the callout fails for some reason, such as misconfiguration, these variables will be set:

| name                  | meaning |
| --------------------- | ---------------------------------------------------------------------- |
| CERTIFICATE            | the string that contains supplied pem certificate                     |
| JAVA_ERROR       | Error message that was generated                                            |
| JAVA_STACKTRACE       | a human-readable exception stacktrace                                  |


## Using the Policy



## Examples

See the attached [bundle](./eidas-certificate-bundle) for a working API Proxy.
To try out the following scenarios, deploy that proxy to any org and environment.

### Parsing a certificate


Send a request like this:

Example success case:
```
$ curl -H 'SSL_CLIENT_CERT: -----BEGIN CERTIFICATE-----\nMIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\nREUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\nDAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\nQ0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\nMTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l\nMQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w\nDQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz\nNDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygUI6R+8LEMgB\n4mVPKCq9a7AW1UuTXSXb4/GehFi+fWmcaUCUqrLamPUZKEelW2LZ92dSb/uFKA56\nYpI0kEcEwjE0DUl/7oZsdPKeSxPfixOpuj9m3V3VZIDbYxgKjnaxWHkobXCIzhHp\n7AQ6cMpPY7i4O+IXK4bY4cqImW/jBiHhV1tkAHCrRyQgb9aRDFN1CqyUdL9XBzC7\noO/GdVlfJPX8YlQz9Dd9PrXL0ORsvms2wRArVFgiDIPNcgJKGIOigHTzb66WIutu\nmBYrMcObXf+9Mb7q2KUeRFizKlO7t9H3vDmKi+nYJLNXDbJLf6+kRJj5EfMOP/MG\nXGluValZAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG\nBwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG\nUFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG\n9w0BAQsFAAOCAQEAesGPHrsobCiPqA49tYzDpgWFm33C+9bTqisRd07bCjWWKLpw\nZsQjxZqTUVSaHedXjxF92JdWgcTtW2jhjYIiEixfaUkoEgpqPfPhDTuqpdw2dD2z\n/N0bdVuxIhxatwA/4Dh0zMO0e3GTmK0iMcRczaPuiCQiDuEaoKy+ZpDzdGfrsmDx\n5wKhIdJ/HoV/fi3gjnUcBUFI3n9MZxinPfIvbouHkRpBtyN8T25NGdpKgLX5P3l9\nyE+a+3BoVXBsDgmkuf5pkcagyWC53vZRwceBKEaRzVELmL+/9ftRm6d/DT54tCiR\nQ1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\n-----END CERTIFICATE-----' http://$ORG-$ENV.apigee.net/eidas-parse-certificate


{
    "certInfo": {
        "basicConstraints": "CA: true",
        "subject": "OID.2.5.4.97=12345987, L=Nuremberg, ST=Bayern, C=Germany, OU=ou, O=org, CN=domainName",
        "issuer": "EMAILADDRESS=ca@test.de, CN=Authority CA Domain Name, OU=IT, O=Authority CA, L=Frankfurt, ST=Hessen, C=DE",
        "validFrom": 1543573407000,
        "expiryDate": 1543573407000,
        "isValid": "<TODO>",
        "publicKey": "RSA, 2048",
        "serialNumber": 1875022970,
        "sigAlgName": "SHA256withRSA",
        "version": 3,
        "fingerprintSha256": "8519974939ccb1d2880bd8d635beffb7e0725fbc7d3af4ef2b8e9df88deeae7b",
        "fingerprintSha1": "b8f6a5c8b18a3e1b058f4ebd458683094caeacce",
        "rolesOfPSP": "[\"PSP_AS\",\"PSP_PI\",\"PSP_AI\",\"PSP_IC\"]"
    }
}
```



# eidaspsd cli utility

The /bin/eidaspsd utility supports collection of operations to facilitate management of eiDAS/PSD2 certificates. Due to the fact that eiDAS statements are qcExtentions in the ASN.1 format, it is not possible to see or manipulate its contents with most of the utilities, ie, openssl, cfssl, keytool, etc.

Using the utility, you can now display salient fields of a certficiate and change/set up PSD2 fields.

What's important for PSD2-related SDLC workflows, you can create invalid field values so that you can conduct negative tests.


## Create a private key and certificate from json definition file

Assuming cert.json contains:
```
{
  "certInfo": {
    "basicConstraints": "CA: true",
    "subject": "L=London, ST=London, C=UK, OU=ou, O=org, CN=exco.com, organizationIdentifier=12345987",
    "issuer": "EMAILADDRESS=ca@exco.com, CN=Authority CA Domain Name, OU=IT, O=Authority CA, L=London, ST=London, C=UK",
    "validFrom": 1543573407000,
    "expiryDate": 1543573407000,
    "publicKey": "RSA, 2048",
    "serialNumber": 1875022970,
    "ncaName": "ncaname",
    "ncaId": "ncaid",
    "rolesOfPSP": ["PSP_AS","PSP_PI"]
  }
}
```
Executing following command
```
java -jar eidaspsd.jar create --json=../doc/certificates/cert.json --passphrase=Welcome123
```
Generates following output
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,F330B064FFD528B2BBB21D897EEF54D5

gJFDbq+nGaOy6hauYeDXZ5jkPv3uDQnEwgN0yGkXqDxJUu3OOsa+3HI+DAavMSIX
S+W27wWYcAIylyr+n6lT5kiLjspPG7CrTzyh8xfIe5NPr0KNRoW7FIyp7qOa6ylj
+F7MPTkiDAoJDu1Cr3k3qbtL374EbsouuDjcibJafhcr5Ia141FJbRG/cQGhcO1l
NFF39fvQ6ALJ5lRc/9tR5kYdlDKM3/4ucdSFSMX4SLsnBXu+ki6G761fiBSrXihs
2fUt4xf/RINGsUQmaQzNGJshTEBimerVlb+aKKIE+30A5E3fasaClSLHlOa8PIV9
e+Wo7XLJOQiyQCgIvQdy1o7pVz8+NjCok4RvCWprxYOMVZmGfFMup5sxpJc+wg2n
lyAjOvtHhFwpXYExtJ+INn+VdUD61hgTX+jdQc9hfNsTUzDrM8dNwUuIQG+QR6aj
EUKieT2tSyOnGCfNJO9IssXTPonV/dFjCHXpasEVxicvq5CBGuZFLAm8/mpAkypP
0m10EcR+rWxgnjqRnHM3RjBf8a9iVjdo8rIu2Izla/Ui7YM4db/sKsSl3yq4DMfK
PrO6irntsQmow63LgZ0OwqL2nP8yrt8WqQBc6q9darGNqUZ+/4k6PHUmZmfqVlH5
P2g4z3svbR88z1M94n1MU4tFTU0TdR/R70cMI/9gKHliPoo/J1Jo8UI5dTnAAvMZ
PWK9QsDI4VJaHYgsx4DNE+oywScenbDR6z4P3v9+F/E34siKfgphN7nSoP0cqsFn
G62b2vRY39fyZLm+TaHXMQIm0I3jQNv8xN54GSchC9CrT5njhIGU8Fi+FCBWARt/
4/dJ3UfvjWr/qZPWL3IcMNwGhpD0qfKYpUzcCNqgXMoAtjBUWY9REcdBeEHJRXIR
dHoNjzhTnomKSflEXjuohZlk8UbZQNEdAa9mVf3iEJbcwQdckygxbq0FZWcAQWW/
z4KouZ8scmgP5dQ/BPF+BzmOZO9UAJ3MzmksR3F/AIq4QeGQViE9TPhRK1w1Y81C
pj/IGk1Fx5ksu2ECXJB6cXbW7Ndek7FbpsrpYVsH4mj9bpvCQ2a5O83+dJl/vyeD
xFqm5wRrWYm2xau62vFCzOJtwocGn1ip2IaEVnSV8ClUWBodqVrVV+kX04PZctca
deqtLyDnx9OHkg6XxmkQG1KPWVLBUZq/zyJCKE7FKepw/6IQ3wJ3TbHvx6tbGvG3
+H2+dyNPACZrWd3uSWfaUVN5v9GVKMt+wIeJWG2YBvnP49NLlkCajFvXIC/LC0Xi
L4XR1naYWG8oK2+F0h7nxgI2I8HTRm3Gv6ZgyjjK3TyP28fP4Ej34i390byR0vWA
iT6IVfiD9g3VqnBdP/A3gXVNfXMx7sTqxt/QEDQsXO5KTw582oY5ZShXDZ0nLlN8
j7SKTcPj7NhFTe5vY6fEHoiJQYPwqj0T5rfpvPEuy6GFRtxeZTMqyvCdFmddlsf5
9kpjD1iFeIibpoDUVrBk2FAYfz/WxqyRmPIwiyja0Rn2aMghXMtkl8hDjS+5QQqr
E1aj0hkiRRnLVOKRP/bgcdp1RmQ6yi0HRVKIB9vIeePN3ekSk9aI/NFmOljiJe4F
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
MIID5TCCAs2gAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADCBkjEaMBgGCSqGSIb3
DQEJARYLY2FAZXhjby5jb20xITAfBgNVBAMMGEF1dGhvcml0eSBDQSBEb21haW4g
TmFtZTELMAkGA1UECwwCSVQxFTATBgNVBAoMDEF1dGhvcml0eSBDQTEPMA0GA1UE
BwwGTG9uZG9uMQ8wDQYDVQQIDAZMb25kb24xCzAJBgNVBAYTAlVLMB4XDTE4MTEz
MDEwMjMyN1oXDTE4MTEzMDEwMjMyN1owcDEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYD
VQQIDAZMb25kb24xCzAJBgNVBAYTAlVLMQswCQYDVQQLDAJvdTEMMAoGA1UECgwD
b3JnMREwDwYDVQQDDAhleGNvLmNvbTERMA8GA1UEYQwIMTIzNDU5ODcwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFBWq9Ikam+ShADHmSBoozbHvbZiWJ
xQjVSxjv0X/VAj0QoZ8puIUsG/7VuELucYiU2xWH09j3ehB6sKFpCLPB/C3/VqXQ
yhFDXtSnYQx8EqoWcL/FRkpIgMBRdbBEtasEoLpEE40pdbZTEYBu64y3NPzmpsQj
TEbmKHZ+aq1JGfkDPBdpW2p9UOG/EOn2tVo7AMT4NxeV3N1Zkz9mH/S+LlF2MEj7
vruK8ZpmKSx5/7IG7nZ5wHxPxDSeqx5yiA/S1g6TDhyQV1agIvrY+BwsvJAikXW7
DFotIJYrHPrSLRV4vYUikQinUQzsbDGGUUjykSA3nkCumpGKGcU7D04ZAgMBAAGj
ZDBiMAwGA1UdEwQFMAMBAf8wUgYIKwYBBQUHAQMERjBEMEIGBgQAgZgnAjA4MCYw
EQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSQwHbmNhbmFtZQwF
bmNhaWQwDQYJKoZIhvcNAQEFBQADggEBAI9L9RRM5+GJya9xV5EV5TmfRXY9uJ/N
Awjym1BmOEUzsZPoIWXCeRkpSPX7XgyLQtPZ8Q+ItQmB+vHJm2rkURNFBw4fHcFo
aSYGuj0ftswHqUhGiRi/7V/7D3aWv9ok1zFF3wFCaM60nGjTBp8VsjpEyZAbo84T
5AIQjo/Y6FU42Uv0W3iEoC0IjPnbEuN30Z9LoECgJ4o3lFfKrgAXOhwIsk62Xog4
qn0TviLeK4pQlCGk40AjUb5+eycr0M2k6VeiC5xoxTpRiLVZL1T6VYau7jeApLAh
zrE1FjcC+B4trR5n2RNpJ7khr+hQ2nFEXjKVGrk9WNZux1gTzzpqxP0=
-----END CERTIFICATE-----
```






## Show contents of the certificate

```
java -jar eidaspsd.jar show --cert=../doc/certificates/gennedcert.pem
{
  "certInfo": {
    "basicConstraints": "CA: true",
    "subject": "OID.2.5.4.97\u003d12345987, L\u003dNuremberg, ST\u003dBayern, C\u003dGermany, OU\u003dou, O\u003dorg, CN\u003ddomainName",
    "issuer": "EMAILADDRESS\u003dca@test.de, CN\u003dAuthority CA Domain Name, OU\u003dIT, O\u003dAuthority CA, L\u003dFrankfurt, ST\u003dHessen, C\u003dDE",
    "validFrom": 1543573407000,
    "expiryDate": 1543573407000,
    "isValid": "\u003cTODO\u003e",
    "publicKey": "RSA, 2048",
    "serialNumber": 1875022970,
    "sigAlgName": "SHA1withRSA",
    "version": 3,
    "fingerprintSha256": "cb6e5414fcd99fe84ea7aa6cbb4ddf1d2dd4b9835b4f39a6a4f996dd346741ad",
    "fingerprintSha1": "d4a49b90e526c9c5ec926072aebba7d7344a4494",
    "ncaName": "Auth",
    "ncaId": "Germany",
    "rolesOfPSP": "[\"PSP_AS\",\"PSP_PI\",\"PSP_AI\",\"PSP_IC\"]"
  }
}
```

## Edit psd2 fields and sign new certificate with a private key

```
java -jar eidaspsd.jar set --cert=../doc/certificates/gennedcert.pem --key=../doc/certificates/key.pem --passphrase=Welcome123 --roles=PSP_PI --ncaname=ncaname --ncaid=ncaid
-----BEGIN CERTIFICATE-----
MIID0DCCArigAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADCBlDELMAkGA1UEBhMC
REUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK
DAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg
Q0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx
MTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l
MQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w
DQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz
NDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzezfS9BIdspq9
wa4oxGo+aMxBVYOxLR4h/9X4hU/8fnxgq7BIrVKbgeckcjPcRhr+ULeJmkemQJnh
wLqlmdAtcmbhU16dKnIAYV9YhIe3HEr1s7LUeKt2qEMyXXQvz9RGFOkceqDqGqSR
GwBlRMOmPTvVsVYyzqhSh4SiLFWOO3U4ZZy47ymgSgVvRE+Vg8A3YWkS/605LU6p
0IIA1PPg7ym3/8fZ6C8UTXuFIoXn+ukOGiEE9tGHqSr4IrlNtb3fMbRWW/pR109D
uNLAqFByjYzR+unbWZ0qCgwVnddIcupGehmnEcNkx8hTLAbdYk4b16cy7RWxoSj0
FahPt59zAgMBAAGjQzBBMD8GCCsGAQUFBwEDBDMwMTAvBgYEAIGYJwIwJTATMBEG
BwQAgZgnAQIMBlBTUF9QSQwHbmNhbmFtZQwFbmNhaWQwDQYJKoZIhvcNAQEFBQAD
ggEBAFpcDJXxFvkrGylb3a5e/e+oxG6xhe6zYNgkXBsBfuHCTvZEgTV2jckfEeU8
YKr9qgmQcUpeoKsDpXSzZFGFcA1KQUUK2YkB3T7chb3l08EynQ6aCb9i2/5QhNgd
U+2qzBD/I4he5c3oQJKjs51u0QZa+Bkv8dBmfdjhGCdq+u3VmLUkmSFa6uUZ2S3K
c8qg86h9cWcfQH2H26yqlyDath3877/87KW2m3E+TVJQXVvVzo9WdPwZE/gZEOBb
IOUvz4qFbf4wGJ5cfAtlOXvbElfSRk31Wg1MRQoIvaqPGiM45iF3pf7P66AnFE1k
FyPdGiDSA/7uEXmrsNve4ity11k=
-----END CERTIFICATE-----
```

## Verify edited values
```
 java -jar eidaspsd.jar show --cert=/tmp/cert.pem
{
  "certInfo": {
    "basicConstraints": "CA: true",
    "subject": "OID.2.5.4.97\u003d12345987, L\u003dNuremberg, ST\u003dBayern, C\u003dGermany, OU\u003dou, O\u003dorg, CN\u003ddomainName",
    "issuer": "EMAILADDRESS\u003dca@test.de, CN\u003dAuthority CA Domain Name, OU\u003dIT, O\u003dAuthority CA, L\u003dFrankfurt, ST\u003dHessen, C\u003dDE",
    "validFrom": 1543573407000,
    "expiryDate": 1543573407000,
    "isValid": "\u003cTODO\u003e",
    "publicKey": "RSA, 2048",
    "serialNumber": 1875022970,
    "sigAlgName": "SHA1withRSA",
    "version": 3,
    "fingerprintSha256": "8345ed6b67056bb641e6ccac5a0579acdf80663de59f7b92f561b66bb6d8876b",
    "fingerprintSha1": "cc1adb500568facbff32b475161936dc5becfc4b",
    "ncaName": "ncaname",
    "ncaId": "ncaid",
    "rolesOfPSP": "[\"PSP_PI\"]"
  }
}
```

## Set up/overwrite organizationIdentifier/2.5.4.97
```
java -jar eidaspsd.jar set --cert=../doc/certificates/gennedcert.pem --key=../doc/certificates/key.pem  --passphrase=Welcome123 --roles=PSP_PI --ncaname=ncaname --ncaid=ncaid --organizationidentifier=PSDES-BDE-3DFD21
```


## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is copyright 2018, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

## Status

This is a community supported project. There is no warranty for this code.
If you have problems or questions, ask on [commmunity.apigee.com](https://community.apigee.com).
