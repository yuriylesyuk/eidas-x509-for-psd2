package com.exco.eidas;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;

import mockit.Mock;
import mockit.MockUp;

public class EiDASCertificateParserCalloutTest {

	Message message;
	MessageContext messageContext;
	ExecutionContext executionContext;

	@Before
	public void testSetup() {

		message = new MockUp<Message>() {

			private Map<String, Object> headers;

			public void $init() {
				getHeaders();
			}

			private Map<String, Object> getHeaders() {
				if (headers == null) {
					headers = new HashMap<String, Object>();
				}
				return headers;
			}

			@Mock
			public String getHeader(final String name) {
				return (String) getHeaders().get(name);
			}

			@Mock
			public boolean setHeader(final String name, final Object value) {
				getHeaders().put(name, value);
				return true;
			}

		}.getMockInstance();

		messageContext = new MockUp<MessageContext>() {

			private Map<String, Object> variables;

			public void $init() {
				getVariables();

			}

			private Map<String, Object> getVariables() {
				if (variables == null) {
					variables = new HashMap<String, Object>();
				}
				return variables;
			}

			@Mock
			public Object getVariable(final String name) {
				return getVariables().get(name);
			}

			@Mock
			public boolean setVariable(final String name, final Object value) {
				getVariables().put(name, value);
				return true;
			}

			@Mock
			public Message getMessage() {
				return message;
			}

		}.getMockInstance();

		executionContext = new MockUp<ExecutionContext>() {
		}.getMockInstance();
	}

	
	@Test
	public void parsePsd2Certificate() {

		messageContext.setVariable("request.header.SSL-CLIENT-CERT",
				// cert with no type				
				"-----BEGIN CERTIFICATE-----\\n"
				+ "MIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC"
				+ "REUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK"
				+ "DAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg"
				+ "Q0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx"
				+ "MTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l"
				+ "MQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w"
				+ "DQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz"
				+ "NDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygUI6R+8LEMgB"
				+ "4mVPKCq9a7AW1UuTXSXb4/GehFi+fWmcaUCUqrLamPUZKEelW2LZ92dSb/uFKA56"
				+ "YpI0kEcEwjE0DUl/7oZsdPKeSxPfixOpuj9m3V3VZIDbYxgKjnaxWHkobXCIzhHp"
				+ "7AQ6cMpPY7i4O+IXK4bY4cqImW/jBiHhV1tkAHCrRyQgb9aRDFN1CqyUdL9XBzC7"
				+ "oO/GdVlfJPX8YlQz9Dd9PrXL0ORsvms2wRArVFgiDIPNcgJKGIOigHTzb66WIutu"
				+ "mBYrMcObXf+9Mb7q2KUeRFizKlO7t9H3vDmKi+nYJLNXDbJLf6+kRJj5EfMOP/MG"
				+ "XGluValZAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG"
				+ "BwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG"
				+ "UFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG"
				+ "9w0BAQsFAAOCAQEAesGPHrsobCiPqA49tYzDpgWFm33C+9bTqisRd07bCjWWKLpw"
				+ "ZsQjxZqTUVSaHedXjxF92JdWgcTtW2jhjYIiEixfaUkoEgpqPfPhDTuqpdw2dD2z"
				+ "/N0bdVuxIhxatwA/4Dh0zMO0e3GTmK0iMcRczaPuiCQiDuEaoKy+ZpDzdGfrsmDx"
				+ "5wKhIdJ/HoV/fi3gjnUcBUFI3n9MZxinPfIvbouHkRpBtyN8T25NGdpKgLX5P3l9"
				+ "yE+a+3BoVXBsDgmkuf5pkcagyWC53vZRwceBKEaRzVELmL+/9ftRm6d/DT54tCiR"
				+ "Q1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\\n"
				+ "-----END CERTIFICATE-----"
				
		);

		Map<String, String> properties = new HashMap<String, String>();
		
		properties.put("operation", "show");

		properties.put("certificate-pem", "request.header.SSL-CLIENT-CERT");
		properties.put("certificate-info", "context.certinfo");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		// TODO
		assertEquals(
				
			// without qctypes
				"{\n" + 
				"  \"certInfo\": {\n" + 
				"    \"basicConstraints\": \"CA: false\",\n" + 
				"    \"subject\": \"organizationIdentifier=12345987, L=Nuremberg, ST=Bayern, C=Germany, OU=ou, O=org, CN=domainName\",\n" + 
				"    \"issuer\": \"EMAILADDRESS=ca@test.de, CN=Authority CA Domain Name, OU=IT, O=Authority CA, L=Frankfurt, ST=Hessen, C=DE\",\n" + 
				"    \"validFrom\": 1542102178000,\n" + 
				"    \"expiryDate\": 1543573407000,\n" + 
				"    \"isValid\": \"<TODO>\",\n" + 
				"    \"publicKey\": \"RSA, 2048\",\n" + 
				"    \"serialNumber\": 1875022970,\n" + 
				"    \"sigAlgName\": \"SHA256withRSA\",\n" + 
				"    \"version\": 3,\n" + 
				"    \"fingerprintSha256\": \"8519974939ccb1d2880bd8d635beffb7e0725fbc7d3af4ef2b8e9df88deeae7b\",\n" + 
				"    \"fingerprintSha1\": \"b8f6a5c8b18a3e1b058f4ebd458683094caeacce\",\n" + 
				"    \"ncaName\": \"Auth\",\n" + 
				"    \"ncaId\": \"Germany\",\n" + 
				"    \"rolesOfPSP\": [\n" + 
				"      \"PSP_AS\",\n" + 
				"      \"PSP_PI\",\n" + 
				"      \"PSP_AI\",\n" + 
				"      \"PSP_IC\"\n" + 
				"    ]\n" + 
				"  }\n" + 
				"}"
				
				, messageContext.getVariable("context.certinfo")
		);
	}

	
	@Test
	public void parsePsd2CertificateWithQcTypesAndPSD2Roles() {

		messageContext.setVariable("request.header.SSL-CLIENT-CERT",
				// cert with qctypes
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIIEHjCCAwagAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJV\n" + 
				"SzEPMA0GA1UEBwwGTG9uZG9uMREwDwYDVQQKDAhFeGNvIFBMQzEgMB4GA1UECwwX\n" + 
				"Q0EgU2VydmljZXMvSW50ZXJtIERlc2sxFzAVBgNVBAMMDkV4Y28tSW50ZXJtLUNB\n" + 
				"MB4XDTE4MTEzMDEwMjMyN1oXDTE5MDYwNTEzMTE0Nlowga8xGTAXBgkqhkiG9w0B\n" + 
				"CQEWCmNhQHRlc3QuZGUxITAfBgNVBAMMGEF1dGhvcml0eSBDQSBEb21haW4gTmFt\n" + 
				"ZTELMAkGA1UECwwCSVQxFTATBgNVBAoMDEF1dGhvcml0eSBDQTESMBAGA1UEBwwJ\n" + 
				"RnJhbmtmdXJ0MQ8wDQYDVQQIDAZIZXNzZW4xCzAJBgNVBAYTAkRFMRkwFwYDVQRh\n" + 
				"DBBQU0RFUy1CREUtM0RGRDIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" + 
				"AQEAs8qjpI1XqKf72ejAS6mxra7/k0XvXIBKAaL8i5l8WN7WfiXjEbl/C5pYm2Tt\n" + 
				"3OsqxHBwtqvUttB2wfRG8OtYG348fzzNeXdGCtyfnULj4IYQzlqz3hHxWoAbQ5Eb\n" + 
				"iU2t7V+SbLiY6eGIsSem7Po6pnTJduo/FjXzC0aT4PVM3m9ttxFmpesqeWSo4njQ\n" + 
				"VqnfdGObYwg0HgPR8RMkGwZSrTUB8L3JBDTotx+Hqht8hesHSZNGHDMyVd2h2Got\n" + 
				"6Vc6rImPKxCwtYzHBoMbjq7M3J6KXEMeGpLTOi53cOz2e1tc+Nevf/x50XoibkqY\n" + 
				"yS1GSoFtqe13zJimoHuNAK8bDwIDAQABo4GDMIGAMAwGA1UdEwQFMAMBAf8wcAYI\n" + 
				"KwYBBQUHAQMEZDBiMBwGBgQAjkYBBjASBgcEAI5GAQYCBgcEAI5GAQYDMEIGBgQA\n" + 
				"gZgnAjA4MCYwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSQwH\n" + 
				"bmNhbmFtZQwFbmNhaWQwDQYJKoZIhvcNAQEFBQADggEBAJtzg3+gbxJCnW3O5Z4N\n" + 
				"UD7hkmlIZeLO1hoWx02xkf7U2TCfdFQnRIDZf/k8KgOAcDjpcrqyBoUdaqRIR9qy\n" + 
				"y2qBjoDyblDgwUm2DAs0GtlEoOCxHKinPgRVUDsHfmyUsEJZjr7ZPkMRGyfq2pE9\n" + 
				"tL2HFxZjhUTbbY+pYXSSLhFo5bKyMulxxqW/J8IRiulXwGC8k9I4gzG45elci5MJ\n" + 
				"ynW6+5/wWrXrpyF1YSErgP2yLZFYy/u2FNbNUDwaEz5oJA0Ny1MsVMTBDe2nyRtX\n" + 
				"ViJU7mENDV6x6LPIngFPt8hIc0EANr1Z/uzMlA+DA4XQxhg+KZRaIfW1653Zq1HM\n" + 
				"0Do=\n" + 
				"-----END CERTIFICATE-----"			

				);

		Map<String, String> properties = new HashMap<String, String>();
		
		properties.put("operation", "show");

		properties.put("certificate-pem", "request.header.SSL-CLIENT-CERT");
		properties.put("certificate-info", "context.certinfo");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		assertEquals(
				"{\n" + 
				"  \"certInfo\": {\n" + 
				"    \"basicConstraints\": \"CA: true\",\n" + 
				"    \"subject\": \"organizationIdentifier=PSDES-BDE-3DFD21, C=DE, ST=Hessen, L=Frankfurt, O=Authority CA, OU=IT, CN=Authority CA Domain Name, E=ca@test.de\",\n" + 
				"    \"issuer\": \"CN=Exco-Interm-CA, OU=CA Services/Interm Desk, O=Exco PLC, L=London, C=UK\",\n" + 
				"    \"validFrom\": 1543573407000,\n" + 
				"    \"expiryDate\": 1559740306000,\n" + 
				"    \"isValid\": \"<TODO>\",\n" + 
				"    \"publicKey\": \"RSA, 2048\",\n" + 
				"    \"serialNumber\": 1875022970,\n" + 
				"    \"sigAlgName\": \"SHA1withRSA\",\n" + 
				"    \"version\": 3,\n" + 
				"    \"fingerprintSha256\": \"357c4c53c3aa567b4c19346e2570aaf004ed9362f4bd28c8d5232da319ac9776\",\n" + 
				"    \"fingerprintSha1\": \"215ef1f43a7585f68556b2067a4e746c8bc38b8c\",\n" + 
				"    \"qcTypes\": [\n" + 
				"      \"eSeal\",\n" + 
				"      \"eWeb\"\n" + 
				"    ],\n" + 
				"    \"ncaName\": \"ncaname\",\n" + 
				"    \"ncaId\": \"ncaid\",\n" + 
				"    \"rolesOfPSP\": [\n" + 
				"      \"PSP_AS\",\n" + 
				"      \"PSP_PI\"\n" + 
				"    ]\n" +
				"  }\n" + 
				"}"
				, messageContext.getVariable("context.certinfo")
		);
	}

	
	@Test
	public void parsePsd2CertificateWithKEandEKUandQcTypesAndPSD2Roles() {

		messageContext.setVariable("request.header.SSL-CLIENT-CERT",
				// cert with qctypes
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIIEMjCCAxqgAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJV\n" + 
				"SzEPMA0GA1UEBwwGTG9uZG9uMREwDwYDVQQKDAhFeGNvIFBMQzEgMB4GA1UECwwX\n" + 
				"Q0EgU2VydmljZXMvSW50ZXJtIERlc2sxFzAVBgNVBAMMDkV4Y28tSW50ZXJtLUNB\n" + 
				"MB4XDTE4MTEzMDEwMjMyN1oXDTE5MDYwNTEzMTE0Nlowga8xGTAXBgkqhkiG9w0B\n" + 
				"CQEWCmNhQHRlc3QuZGUxITAfBgNVBAMMGEF1dGhvcml0eSBDQSBEb21haW4gTmFt\n" + 
				"ZTELMAkGA1UECwwCSVQxFTATBgNVBAoMDEF1dGhvcml0eSBDQTESMBAGA1UEBwwJ\n" + 
				"RnJhbmtmdXJ0MQ8wDQYDVQQIDAZIZXNzZW4xCzAJBgNVBAYTAkRFMRkwFwYDVQRh\n" + 
				"DBBQU0RFUy1CREUtM0RGRDIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" + 
				"AQEAlfTKcv2bmQ8J7bJoD3rgoYMWSbhtgmd4X876ThUiY2FO2fDaGYVC2mF6/DSH\n" + 
				"TtayAQpa0mipIK56UfAqdOVqgWDDylOOLs/nf+R0J3ccmSibhC+949v5SI2/iuw0\n" + 
				"VQhvswi+P5ZKv9nhfl4Gyp7l+8zKtl0NSHOEPfpV/KxI3ZOQ9srpi1joiX9/R8u/\n" + 
				"1T4L9QTFIq62GoBcF2pPBrQK5k2nRnMReahivMznNIAQK4bqdKfJAhjrXM3hYoPI\n" + 
				"Le5uV6f46eNJMsTRIucJ2iQorwwVIxVCKx6Fklb1jb3QfuFdlbM/nImZIuTGQXsk\n" + 
				"YrMiqaom5aXm3p0ovOAJ3HT0twIDAQABo4GXMIGUMAwGA1UdEwQFMAMBAf8wDgYD\n" + 
				"VR0PAQH/BAQDAgKEMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBS\n" + 
				"BggrBgEFBQcBAwRGMEQwQgYGBACBmCcCMDgwJjARBgcEAIGYJwEBDAZQU1BfQVMw\n" + 
				"EQYHBACBmCcBAgwGUFNQX1BJDAduY2FuYW1lDAVuY2FpZDANBgkqhkiG9w0BAQUF\n" + 
				"AAOCAQEAPU+w8rWPxgpbm3sT15cGV+Q14sFtH24l71l7fHL367ZqEY5Pu2bnT2QW\n" + 
				"EziUBusBdSKCL2xHCT8XUZoqXDSVxSEeDUIWXVSjWumOKLEuzrGyikBWwzwqmCC5\n" + 
				"NKT6BzDJpIJbDY+rpc4Fk3PizvVfNpS8Qe9wZo46NQX3B9T5rJi3TOjfJm9vprdA\n" + 
				"yzv8h1fVjJHk6tAZjcihBJoZls2o8cYVrTCbPjT+3sz/FIXbTtoMSRLSMCiK+3VQ\n" + 
				"eLpG0X1Rti6PoI1YEyXA3PJhjvw4wzAxqXT3vPHIOmCqZa0r12f5PeCeo+Mbnw/I\n" + 
				"/J/PmxZHgbXBCQshAx4vfIIXqBwXEw==\n" + 
				"-----END CERTIFICATE-----\n"			

				);

		Map<String, String> properties = new HashMap<String, String>();
		
		properties.put("operation", "show");

		properties.put("certificate-pem", "request.header.SSL-CLIENT-CERT");
		properties.put("certificate-info", "context.certinfo");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		assertEquals(
				"{\n" + 
				"  \"certInfo\": {\n" + 
				"    \"basicConstraints\": \"CA: true\",\n" + 
				"    \"subject\": \"organizationIdentifier=PSDES-BDE-3DFD21, C=DE, ST=Hessen, L=Frankfurt, O=Authority CA, OU=IT, CN=Authority CA Domain Name, E=ca@test.de\",\n" + 
				"    \"issuer\": \"CN=Exco-Interm-CA, OU=CA Services/Interm Desk, O=Exco PLC, L=London, C=UK\",\n" + 
				"    \"validFrom\": 1543573407000,\n" + 
				"    \"expiryDate\": 1559740306000,\n" + 
				"    \"isValid\": \"<TODO>\",\n" + 
				"    \"publicKey\": \"RSA, 2048\",\n" + 
				"    \"serialNumber\": 1875022970,\n" + 
				"    \"sigAlgName\": \"SHA1withRSA\",\n" + 
				"    \"version\": 3,\n" + 
				"    \"fingerprintSha256\": \"3f66843bf6e114e83c004055f0c51b826b0518e17f43fea8c010657849ea864f\",\n" + 
				"    \"fingerprintSha1\": \"9c2b35c18432c9e661b398c8f4c79d7b740808f5\",\n" + 
				"    \"keyUsage\": [\n" + 
				"      \"digitalSignature\",\n" + 
				"      \"keyCertSign\"\n" + 
				"    ],\n" + 
				"    \"extKeyUsage\": [\n" + 
				"      \"serverAuth\",\n" + 
				"      \"clientAuth\"\n" + 
				"    ],\n" + 
				"    \"ncaName\": \"ncaname\",\n" + 
				"    \"ncaId\": \"ncaid\",\n" + 
				"    \"rolesOfPSP\": [\n" + 
				"      \"PSP_AS\",\n" + 
				"      \"PSP_PI\"\n" + 
				"    ]\n" + 
				"  }\n" + 
				"}"
				, messageContext.getVariable("context.certinfo")
		);
	}


	@Test
	public void signPsd2CsrAndIssuePsd2Certificate() {
		
		messageContext.setVariable("context.certinfo", "" +
				"{" + 
				"  \"certInfo\": {" + 
				"    \"basicConstraints\": \"CA: true\"," + 
				"    \"subject\": \"emailAddress\\u003dca@test.de, CN\\u003dAuthority CA Domain Name, OU\\u003dIT, O\\u003dAuthority CA, L\\u003dFrankfurt, ST\\u003dHessen, C\\u003dDE, OID.2.5.4.97\\u003dPSDES-BDE-3DFD21\"," +
				"    \"issuer\": \"C\\u003dUK, L\\u003dLondon, O\\u003dExco PLC, OU\\u003dCA Services/Interm Desk, CN\\u003dExco-Interm-CA\","+
				"    \"validFrom\": 1543573407000," + 
				"    \"expiryDate\": 1559740306000," + 
				"    \"isValid\": \"\\u003cTODO\\u003e\"," + 
				"    \"publicKey\": \"RSA, 2048\"," + 
				"    \"serialNumber\": 1875022970," + 
				"    \"sigAlgName\": \"SHA1withRSA\"," + 
				"    \"version\": 3," + 
				"    \"fingerprintSha256\": \"8345ed6b67056bb641e6ccac5a0579acdf80663de59f7b92f561b66bb6d8876b\"," + 
				"    \"fingerprintSha1\": \"cc1adb500568facbff32b475161936dc5becfc4b\"," + 
				"    \"qcTypes\": [\"eSeal\",\"eWeb\"]," + 
				"    \"ncaName\": \"ncaname\"," + 
				"    \"ncaId\": \"ncaid\"," + 
				"    \"rolesOfPSP\": [\"PSP_AS\",\"PSP_PI\"]" + 
				"  }" + 
				"}" 
		);

		// csr with qcTypes
		messageContext.setVariable("request.header.CSR",
				"-----BEGIN CERTIFICATE REQUEST-----\n" + 
				"MIIDRDCCAiwCAQAwejERMA8GA1UEYQwIMTIzNDU5ODcxEjAQBgNVBAcMCU51cmVt\n" + 
				"YmVyZzEPMA0GA1UECAwGQmF5ZXJuMRAwDgYDVQQGEwdHZXJtYW55MQswCQYDVQQL\n" + 
				"DAJvdTEMMAoGA1UECgwDb3JnMRMwEQYDVQQDDApkb21haW5OYW1lMIIBIjANBgkq\n" + 
				"hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8qjpI1XqKf72ejAS6mxra7/k0XvXIBK\n" + 
				"AaL8i5l8WN7WfiXjEbl/C5pYm2Tt3OsqxHBwtqvUttB2wfRG8OtYG348fzzNeXdG\n" + 
				"CtyfnULj4IYQzlqz3hHxWoAbQ5EbiU2t7V+SbLiY6eGIsSem7Po6pnTJduo/FjXz\n" + 
				"C0aT4PVM3m9ttxFmpesqeWSo4njQVqnfdGObYwg0HgPR8RMkGwZSrTUB8L3JBDTo\n" + 
				"tx+Hqht8hesHSZNGHDMyVd2h2Got6Vc6rImPKxCwtYzHBoMbjq7M3J6KXEMeGpLT\n" + 
				"Oi53cOz2e1tc+Nevf/x50XoibkqYyS1GSoFtqe13zJimoHuNAK8bDwIDAQABoIGE\n" + 
				"MIGBBgkqhkiG9w0BCQ4xdDByMHAGCCsGAQUFBwEDBGQwYjAcBgYEAI5GAQYwEgYH\n" + 
				"BACORgEGAgYHBACORgEGAzBCBgYEAIGYJwIwODAmMBEGBwQAgZgnAQEMBlBTUF9B\n" + 
				"UzARBgcEAIGYJwECDAZQU1BfUEkMB25jYW5hbWUMBW5jYWlkMA0GCSqGSIb3DQEB\n" + 
				"CwUAA4IBAQA38Q8IRw+sPzuSe/0YDsZ407hkK/OHnKALvEBTPC7DrtGsolKt9Ss/\n" + 
				"tbpEzkCk0OHcQlMbyLVRuSJa2Irbt6v2S6wfocQzbUVDKYFW8V4hipLDijXIXUvf\n" + 
				"BEVspfzRLD4jHNL3/0k45J+BGrysA9vaMcPOgHO8ZfnG+S8eV2Swf/LX6l1s4wYS\n" + 
				"trY1zlnnBbSLO4IHdMbsos9LwWM4Z8ud33+wJGmchKxZbfMxEmQ/ubNnt0KEJoCj\n" + 
				"eB9N8eVhcG5nK67dX6lUg4n4Zk8ryLKqFextrkWW+jxRXD0G7Zyc3DiolWnJf8GT\n" + 
				"V69eW4ak8LLHoH9VHL2slDGnz0ZdM5WX\n" + 
				"-----END CERTIFICATE REQUEST-----" 
		);
		
		
		messageContext.setVariable("private.privatekey",
				"-----BEGIN RSA PRIVATE KEY-----\n" + 
						"MIIEowIBAAKCAQEAuvYEVs1/k1HsULB5/zSRcXXmECVKVsZCcifvavrTtho6VaEZ\n" + 
						"Mf/AXTce5p5McmxOe2PSCOd8b1qOH1+inqfMKVCJptb5VOAEW2ZSOIHKWggHFqG3\n" + 
						"nMN9G+rdMKc+jwtJmLmeI1DvkrjkyDaYSsYsfg0tCswBijhcof7dGSyYHBmR6njP\n" + 
						"9qMIWky/h3v55uU0oBPXoFjrRhIHNASLbLY/v+8ADbI9vAfK5p9ccNAbt9sTXwGV\n" + 
						"jVEJ0KLMZQsOFsmAelBIU8TSiYpJS53IGtbL8wEnCgbcWFKYOfRar+NBKjJ52pBd\n" + 
						"DWrFV5VDbfWvvaZ/NKCta5RU0lJgiYbj340dgwIDAQABAoIBAGUPy3SojMezxwwu\n" + 
						"+SNM5TnxwzUDE1YowY43rCGmCH8tWk8jUB1I5FD/FMMQ2r4Xca0dXlHV39vJlX28\n" + 
						"Eom0ppXGpUH8fra0iWZmvxcwgZN9N2eybzBcM+q9YGeGYDiun0/hNmxcucQUEgdw\n" + 
						"C46P5UkWEjz93e87XEdtH1MWWfsFoX+ViyAC/3UKRMvB2ELCeOQtpLH9gQrlkIFh\n" + 
						"dS3kUgjQgwJuoWcbVIQ1g8vgRjtTQOZqm6MuREVa1Khcyg5uwn7PEJjV/xyQaBny\n" + 
						"zA8S52RV1Rsx+a9ka8LhS56n5vgA/HTodgVarsUMASk6GKYu42LBQ1PiNTtxFKNC\n" + 
						"CO7/isECgYEAxC8sghNygQ/18sWjsDzr8sqOqvqMyLqsyC/b1DhfPgNCViZ4wrEw\n" + 
						"LWpjcy2h/gjD4MtICiJFWkMAAPsddfXRB6II0aNAksM1kr8kWSWJXP4XrPZVBsGl\n" + 
						"/mJwDpgFkO6uABP843DnPHvmcBD/9gCHi5f2rONOJzuHW++PZLsBhvMCgYEA8/bv\n" + 
						"yaJlu4lXFw7jK6QzpgAx72oT2yU9XHMRrI66/ac1VE7HzBSQR5FKlKHNG+FYozk2\n" + 
						"GOWTdUEDr2VZwURFxcs++/VOljZI4tCN6a08CyM9CB/tohHES4Nz1QDu3GLUPJHG\n" + 
						"HEcFbynLQKUvaDHfcyFg0C4MrWV+JMj593fY0zECgYBdcp7/wqWrJmAf6NaEjzBQ\n" + 
						"sP1uIfRHdOvyWyGaH9P2JPVHNgIVsvLg3ylJ5rWf3Kr4+7tv4E0qpnls/jBVTObp\n" + 
						"fNw4h0ut3MA7C0MUF5Yrrni2kYuEsV8RIfCAcxdLpvVI4jx2VgQ/QkFMpjxWAICQ\n" + 
						"FK2SQp+qfmeGekDSWWVr0wKBgQCzlFSDlr/N4NWzimjb6f1+tuwK8Il3KZ1WXPlo\n" + 
						"jJPGPPu7eFYHuidOFvvQFp31ZNYrJ+TTRMJbcCT3SeJcqhW199r/+l0DoyfZlWyw\n" + 
						"0qy9Ag5d2arBPtTARR3Rb+NjZHgXsbIjhH/SiPAtQKp5xyRVCf/KnesFBA1rpGij\n" + 
						"qZt4MQKBgFK4S3LMP7rlNkvHmRZ+6oz0Dquz5qza/60B0wl2/QiR/xv8bfC3RX+E\n" + 
						"aYd6zLNMPEHmVy49bCeNKtEcjiJOWP+zpDIr6bjvgH3cLsVM1bn5GS9eYUIsaARb\n" + 
						"eZc6juNzKPKZhY4MKm9daoWE6lGs02tkdD6pVaB5K6GIIT4LuZML\n" + 
						"-----END RSA PRIVATE KEY-----"
				);

		messageContext.setVariable("context.certificate", null );

		Map<String, String> properties = new HashMap<String, String>();

		// Input Parameters:
		properties.put("operation", "sign");
		properties.put("request-pem", "request.header.CSR");
		properties.put("certificate-info", "context.certinfo");
		properties.put("privatekey-pem", "private.privatekey");
		properties.put("privatekey-passphrase", "private.privatekey-passphrase");
		
		// Output Parameters:
		properties.put("certificate-pem", "context.certificate");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		// TODO
		assertEquals(
				
				// cert with no types				
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIIEHjCCAwagAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJV\n" + 
				"SzEPMA0GA1UEBwwGTG9uZG9uMREwDwYDVQQKDAhFeGNvIFBMQzEgMB4GA1UECwwX\n" + 
				"Q0EgU2VydmljZXMvSW50ZXJtIERlc2sxFzAVBgNVBAMMDkV4Y28tSW50ZXJtLUNB\n" + 
				"MB4XDTE4MTEzMDEwMjMyN1oXDTE5MDYwNTEzMTE0Nlowga8xGTAXBgkqhkiG9w0B\n" + 
				"CQEWCmNhQHRlc3QuZGUxITAfBgNVBAMMGEF1dGhvcml0eSBDQSBEb21haW4gTmFt\n" + 
				"ZTELMAkGA1UECwwCSVQxFTATBgNVBAoMDEF1dGhvcml0eSBDQTESMBAGA1UEBwwJ\n" + 
				"RnJhbmtmdXJ0MQ8wDQYDVQQIDAZIZXNzZW4xCzAJBgNVBAYTAkRFMRkwFwYDVQRh\n" + 
				"DBBQU0RFUy1CREUtM0RGRDIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" + 
				"AQEAs8qjpI1XqKf72ejAS6mxra7/k0XvXIBKAaL8i5l8WN7WfiXjEbl/C5pYm2Tt\n" + 
				"3OsqxHBwtqvUttB2wfRG8OtYG348fzzNeXdGCtyfnULj4IYQzlqz3hHxWoAbQ5Eb\n" + 
				"iU2t7V+SbLiY6eGIsSem7Po6pnTJduo/FjXzC0aT4PVM3m9ttxFmpesqeWSo4njQ\n" + 
				"VqnfdGObYwg0HgPR8RMkGwZSrTUB8L3JBDTotx+Hqht8hesHSZNGHDMyVd2h2Got\n" + 
				"6Vc6rImPKxCwtYzHBoMbjq7M3J6KXEMeGpLTOi53cOz2e1tc+Nevf/x50XoibkqY\n" + 
				"yS1GSoFtqe13zJimoHuNAK8bDwIDAQABo4GDMIGAMAwGA1UdEwQFMAMBAf8wcAYI\n" + 
				"KwYBBQUHAQMEZDBiMBwGBgQAjkYBBjASBgcEAI5GAQYCBgcEAI5GAQYDMEIGBgQA\n" + 
				"gZgnAjA4MCYwEQYHBACBmCcBAQwGUFNQX0FTMBEGBwQAgZgnAQIMBlBTUF9QSQwH\n" + 
				"bmNhbmFtZQwFbmNhaWQwDQYJKoZIhvcNAQEFBQADggEBAJtzg3+gbxJCnW3O5Z4N\n" + 
				"UD7hkmlIZeLO1hoWx02xkf7U2TCfdFQnRIDZf/k8KgOAcDjpcrqyBoUdaqRIR9qy\n" + 
				"y2qBjoDyblDgwUm2DAs0GtlEoOCxHKinPgRVUDsHfmyUsEJZjr7ZPkMRGyfq2pE9\n" + 
				"tL2HFxZjhUTbbY+pYXSSLhFo5bKyMulxxqW/J8IRiulXwGC8k9I4gzG45elci5MJ\n" + 
				"ynW6+5/wWrXrpyF1YSErgP2yLZFYy/u2FNbNUDwaEz5oJA0Ny1MsVMTBDe2nyRtX\n" + 
				"ViJU7mENDV6x6LPIngFPt8hIc0EANr1Z/uzMlA+DA4XQxhg+KZRaIfW1653Zq1HM\n" + 
				"0Do=\n" + 
				"-----END CERTIFICATE-----\n",				
				
				messageContext.getVariable("context.certificate")
		);
	}
	
	

	
	@Test
	public void parseCertificateWithNoPSD2() {

		messageContext.setVariable("request.header.SSL-CLIENT-CERT",
				// cert with qctypes
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIIDmjCCAoKgAwIBAgIBCTANBgkqhkiG9w0BAQUFADAVMRMwEQYDVQQDDAo4Z3dp\n" + 
				"Zmkub3JnMB4XDTE5MDQzMDE0MTgzNloXDTE5MDUxNDA4MDUxMFowbTELMAkGA1UE\n" + 
				"BhMCQVMxDjAMBgNVBAgTBWRzZGFzMQ4wDAYDVQQHEwVhc2RhczEOMAwGA1UEChMF\n" + 
				"YXNkYXMxDDAKBgNVBAsTA2FkczEMMAoGA1UEAxMDYXNkMRIwEAYJKoZIhvcNAQkB\n" + 
				"FgNhc2QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSLn8SAW1bntdP\n" + 
				"qbZiyvYMuPfsPDT/uXVzTzUMkdAOdr+u7gPyYcS7JxRXjhDnYQRY0cjlEdg1gNN4\n" + 
				"e8yl6FIX7HgHozxvDTKsS3PKDy9H05swatGfaT9VfcxIzhF6l5yCbGazf1DSXGW/\n" + 
				"J3o5w1OHxeclfBEW3byCbetsmdBTVFWQ0G0yiKI8lUpv8wCqtQARWtOV6RVz7Av2\n" + 
				"fENE7PNiKfDFbnNIzIBjP/t+G60TefAgKN0Aosy9jPiApvidFkGvO5M/cLYc7SWV\n" + 
				"MHfyZ6kb/K76tUWO49d4aO5NUBg8z1BbjkvU46+yubw5/YNC9y2LnXwS47RuarAS\n" + 
				"wx78sn2rAgMBAAGjgZwwgZkwPAYDVR0jBDUwM4AUIf0b/ctfAz5BuLqFaVqMki7j\n" + 
				"SbShFaQTMBExDzANBgNVBAMMBnJvb3RDQYIEnNMcnTAdBgNVHQ4EFgQUALiYaqHw\n" + 
				"+Q8OlofG4RkrUKpkXKMwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC\n" + 
				"BaAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEFBQADggEBAHuU\n" + 
				"2xGEUWhljovS8XmCDzKlIfwvoZSpFyYCUZcY8j89S9O2QBvhcJvdk1NbWJQ0Ccso\n" + 
				"MImgqkiqiwrVf/5iq38rc6gCm/IPyTJwkEIxu7xKZ/AR2ltXYQK07yEdK5gy84m3\n" + 
				"zPe4TIIetGuL/y+xmjtX0KKZTb0NsZpGCKofyKc1kAPuXoRS6g45E/QEc19B2Ek7\n" + 
				"ikqjnMgsrMJSsvws42fcgtjCERVD4LZd9GY8EsRYZnyB1AWodf2hDxRHaeTkfqYT\n" + 
				"UdB/2hYyOu9lMCWAA0pSzTViTjCt0ZJlwu10ygpJsdej69Zut4TkUpDiSe6EIxVH\n" + 
				"w6l0WRArO1HWbkQ6aP8=\n" + 
				"-----END CERTIFICATE-----"
				);

		Map<String, String> properties = new HashMap<String, String>();
		
		properties.put("operation", "show");

		properties.put("certificate-pem", "request.header.SSL-CLIENT-CERT");
		properties.put("certificate-info", "context.certinfo");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		assertEquals(
				"{\n" + 
				"  \"certInfo\": {\n" + 
				"    \"basicConstraints\": \"CA: true\",\n" + 
				"    \"subject\": \"E=asd, CN=asd, OU=ads, O=asdas, L=asdas, ST=dsdas, C=AS\",\n" + 
				"    \"issuer\": \"CN=8gwifi.org\",\n" + 
				"    \"validFrom\": 1556633916000,\n" + 
				"    \"expiryDate\": 1557821110000,\n" + 
				"    \"isValid\": \"<TODO>\",\n" + 
				"    \"publicKey\": \"RSA, 2048\",\n" + 
				"    \"serialNumber\": 9,\n" + 
				"    \"sigAlgName\": \"SHA1withRSA\",\n" + 
				"    \"version\": 3,\n" + 
				"    \"fingerprintSha256\": \"6c3b55a6ac47aa2170a46acdddb91641035f41f95c3a5dee8c534c356d18cd61\",\n" + 
				"    \"fingerprintSha1\": \"b9bf34f0ca064271d89153cb2e454513258c8d8a\",\n" + 
				"    \"keyUsage\": [\n" + 
				"      \"digitalSignature\",\n" + 
				"      \"keyEncipherment\"\n" + 
				"    ],\n" + 
				"    \"extKeyUsage\": [\n" + 
				"      \"serverAuth\"\n" + 
				"    ]\n" + 
				"  }\n" + 
				"}"
				, messageContext.getVariable("context.certinfo")
		);
	}

	
}


