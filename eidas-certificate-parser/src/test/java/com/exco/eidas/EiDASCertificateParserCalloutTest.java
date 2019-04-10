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

		messageContext.setVariable("request.header.SSL_CLIENT_CERT",
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
				+ "-----END CERTIFICATE-----");

		Map<String, String> properties = new HashMap<String, String>();

		properties.put("certificate-info", "context.certinfo");
		properties.put("pem-certificate", "request.header.SSL_CLIENT_CERT");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		// TODO
		assertEquals(messageContext.getVariable("context.certinfo"),
				"{\n" + 
				"  \"certInfo\": {\n" + 
				"    \"basicConstraints\": \"CA: false\",\n" + 
				"    \"subject\": \"organizationIdentifier=12345987, L=Nuremberg, ST=Bayern, C=Germany, OU=ou, O=org, CN=domainName\",\n" + 
				"    \"issuer\": \"EMAILADDRESS=ca@test.de, CN=Authority CA Domain Name, OU=IT, O=Authority CA, L=Frankfurt, ST=Hessen, C=DE\",\n" + 
				"    \"validFrom\": 1543573407000,\n" + 
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
				"    \"rolesOfPSP\": \"[\\\"PSP_AS\\\",\\\"PSP_PI\\\",\\\"PSP_AI\\\",\\\"PSP_IC\\\"]\"\n" + 
				"  }\n" + 
				"}");
	}
}
