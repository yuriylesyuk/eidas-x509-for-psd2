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




 





## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is copyright 2018, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

## Status

This is a community supported project. There is no warranty for this code.
If you have problems or questions, ask on [commmunity.apigee.com](https://community.apigee.com).
