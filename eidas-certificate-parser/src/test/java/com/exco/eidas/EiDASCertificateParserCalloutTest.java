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
		
		properties.put("operation", "show");

		properties.put("certificate-pem", "request.header.SSL_CLIENT_CERT");
		properties.put("certificate-info", "context.certinfo");

		EiDASCertificateParserCallout callout = new EiDASCertificateParserCallout(properties);

		callout.execute(messageContext, executionContext);

		// TODO
		assertEquals(
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
				"}", messageContext.getVariable("context.certinfo")
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
				"    \"ncaName\": \"ncaname\"," + 
				"    \"ncaId\": \"ncaid\"," + 
				"    \"rolesOfPSP\": [\"PSP_AS\",\"PSP_PI\"]" + 
				"  }" + 
				"}" 
		);

		messageContext.setVariable("request.header.CSR",
				"-----BEGIN CERTIFICATE REQUEST-----\n" + 
						"MIIDJDCCAgwCAQAwejERMA8GA1UEYQwIMTIzNDU5ODcxEjAQBgNVBAcMCU51cmVt\n" + 
						"YmVyZzEPMA0GA1UECAwGQmF5ZXJuMRAwDgYDVQQGEwdHZXJtYW55MQswCQYDVQQL\n" + 
						"DAJvdTEMMAoGA1UECgwDb3JnMRMwEQYDVQQDDApkb21haW5OYW1lMIIBIjANBgkq\n" + 
						"hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlfTKcv2bmQ8J7bJoD3rgoYMWSbhtgmd4\n" + 
						"X876ThUiY2FO2fDaGYVC2mF6/DSHTtayAQpa0mipIK56UfAqdOVqgWDDylOOLs/n\n" + 
						"f+R0J3ccmSibhC+949v5SI2/iuw0VQhvswi+P5ZKv9nhfl4Gyp7l+8zKtl0NSHOE\n" + 
						"PfpV/KxI3ZOQ9srpi1joiX9/R8u/1T4L9QTFIq62GoBcF2pPBrQK5k2nRnMReahi\n" + 
						"vMznNIAQK4bqdKfJAhjrXM3hYoPILe5uV6f46eNJMsTRIucJ2iQorwwVIxVCKx6F\n" + 
						"klb1jb3QfuFdlbM/nImZIuTGQXskYrMiqaom5aXm3p0ovOAJ3HT0twIDAQABoGUw\n" + 
						"YwYJKoZIhvcNAQkOMVYwVDBSBggrBgEFBQcBAwRGMEQwQgYGBACBmCcCMDgwJjAR\n" + 
						"BgcEAIGYJwEBDAZQU1BfQVMwEQYHBACBmCcBAgwGUFNQX1BJDAduY2FuYW1lDAVu\n" + 
						"Y2FpZDANBgkqhkiG9w0BAQsFAAOCAQEADty06i9b5zrqa/MCiT//uRrklX02RnpQ\n" + 
						"gQAdYqVEzGJH2rqT0cJ6KUtYjO8J60SC4yTiV1+p8lSxUHvS146VU8uEEZO486pG\n" + 
						"ajj6zsdwQDs+uK50uvigNaGTO9Hu5me7F+x2BqDsMlpizJqmqI2W67Sq5MsIaVfF\n" + 
						"031MOVujtC9e/J4n2Hb66lCHat8mRD4bvQqdp07XHpqRDJaFQiz9XIMfjooafhPL\n" + 
						"tX4e8OZP+hm7SjILz5ksrW7vqaRcUa8SJCAqHnezY900NOj7hxNYP71I8aZuE56p\n" + 
						"6iPPQQhrDSIhLvnnrrAhW/UkX1i6j2qbLEt79R4Wr/KKUsBlWHksDQ==\n" + 
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
		assertEquals(messageContext.getVariable("context.certificate"),
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIID/jCCAuagAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJV\n" + 
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
				"YrMiqaom5aXm3p0ovOAJ3HT0twIDAQABo2QwYjAMBgNVHRMEBTADAQH/MFIGCCsG\n" + 
				"AQUFBwEDBEYwRDBCBgYEAIGYJwIwODAmMBEGBwQAgZgnAQEMBlBTUF9BUzARBgcE\n" + 
				"AIGYJwECDAZQU1BfUEkMB25jYW5hbWUMBW5jYWlkMA0GCSqGSIb3DQEBBQUAA4IB\n" + 
				"AQC1s3XqeMnghrgl0Si0s3IlpPA27s42eCa3ko3t3i+6GHLv/oB5EMrZJ0F/2Fum\n" + 
				"Bn9TojcS30u52epDzjYYWMFv4LQm70694MgkA2T+Dd9sa6G13hXoAVFlUChh3Syu\n" + 
				"NrDPQ3GHL0+O7IxneRdivS1fWJ4pL7ANvKFs6vmeTNLfNPI2rtuTC9THh2ENQ6/N\n" + 
				"q8dRik6FI/xzt/RsRjU+wQsLA8ydmAINopi0BlalZjI5WhKUiWxOJsoH+2b1pPiz\n" + 
				"gjNYnqxaIRGlKFqH5o5TFrNKJV4Q0MWXTHynPVAWlaH5fa2GLkTEvPRNY3bGJOoO\n" + 
				"n45lYCv65YwbSXhQUWS5TtXG\n" + 
				"-----END CERTIFICATE-----\n" 
		);
	}
}
