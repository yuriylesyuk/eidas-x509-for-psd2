package com.exco.eidas;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;

public class EiDASCertificateTest {

	String c;
	String k;
	String p;
	
	@Before
	public void testSetup() {
		
		c = "-----BEGIN CERTIFICATE-----\\n"
				+ "MIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\\n"
				+ "REUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\\n"
				+ "DAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\\n"
				+ "Q0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\\n"
				+ "MTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l\\n"
				+ "MQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w\\n"
				+ "DQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz\\n"
				+ "NDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygUI6R+8LEMgB\\n"
				+ "4mVPKCq9a7AW1UuTXSXb4/GehFi+fWmcaUCUqrLamPUZKEelW2LZ92dSb/uFKA56\\n"
				+ "YpI0kEcEwjE0DUl/7oZsdPKeSxPfixOpuj9m3V3VZIDbYxgKjnaxWHkobXCIzhHp\\n"
				+ "7AQ6cMpPY7i4O+IXK4bY4cqImW/jBiHhV1tkAHCrRyQgb9aRDFN1CqyUdL9XBzC7\\n"
				+ "oO/GdVlfJPX8YlQz9Dd9PrXL0ORsvms2wRArVFgiDIPNcgJKGIOigHTzb66WIutu\\n"
				+ "mBYrMcObXf+9Mb7q2KUeRFizKlO7t9H3vDmKi+nYJLNXDbJLf6+kRJj5EfMOP/MG\\n"
				+ "XGluValZAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG\\n"
				+ "BwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG\\n"
				+ "UFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG\\n"
				+ "9w0BAQsFAAOCAQEAesGPHrsobCiPqA49tYzDpgWFm33C+9bTqisRd07bCjWWKLpw\\n"
				+ "ZsQjxZqTUVSaHedXjxF92JdWgcTtW2jhjYIiEixfaUkoEgpqPfPhDTuqpdw2dD2z\\n"
				+ "/N0bdVuxIhxatwA/4Dh0zMO0e3GTmK0iMcRczaPuiCQiDuEaoKy+ZpDzdGfrsmDx\\n"
				+ "5wKhIdJ/HoV/fi3gjnUcBUFI3n9MZxinPfIvbouHkRpBtyN8T25NGdpKgLX5P3l9\\n"
				+ "yE+a+3BoVXBsDgmkuf5pkcagyWC53vZRwceBKEaRzVELmL+/9ftRm6d/DT54tCiR\\n"
				+ "Q1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\\n"
				+ "-----END CERTIFICATE-----\\n";
		
		k = "-----BEGIN RSA PRIVATE KEY-----\n" + 
				"Proc-Type: 4,ENCRYPTED\n" + 
				"DEK-Info: AES-256-CBC,CEB76431E65244905C479719951EBC9F\n" + 
				"\n" + 
				"Hzg6p4bRR7Vk/Re/8R/zpvA9pFaJ/TG2UXhsax/cjvsgfs49zpCDyfczhEcOSpyA\n" + 
				"wycYYlXj4StGKybOfYbUn8H50pWvMi/7m+UL0lUw9Z5BrNlr8p/8FQPYTdOdEkv8\n" + 
				"WNtSQcpZSSyZCDi18Gqshz44Y2HZrWqnO0ODV/dQ60DP1nWh+vGNNVC93fY7FQWb\n" + 
				"J17qdPL9FcX6Frm7To0528WUjY1VnwbNxeNOEeNDHRwGJRFQcwXfCa++2cMjOx2q\n" + 
				"qBvHBShcutd07hDiu2Y4pIPfAOCGcletNXLfZGgNCdHOT6uzY4BrVYmLGje2tYay\n" + 
				"NcOMuDY0pZOKlsbCJ+pT+hXxf9s7Kh7SFBX+EgkdcgGR0Yf+US8LQ8RFoE6m8O+/\n" + 
				"G/wls6IgdbWd2+oXx208SPgecWu9NwtnjT9FbCFedPuq/YXwz+WtmtkpsixpPQSJ\n" + 
				"PujE1l9qWUFDqe4crKVgnoiYjQEEihWm0HWrw/PKA2qBDJdi37MjJeWw2N+NdgAF\n" + 
				"rUM32juUnZiaejKMOnterZWwENAjY6EhfLM7hx2pecU548C+x2T6uIRfNQsKHWk9\n" + 
				"B4qftnjZbX7efygIRLUGWJF/4tnmx7lHq0cZyRV3E8k6b5b7GSSfnYuRZzjliiUd\n" + 
				"euUq2EzsMWPA6eQBK63j2+aXRyVep8SMINIkj/Usx6NJadbFl2h7hvAVk62ThfZ5\n" + 
				"YXctzniwrbFVuuaty8vbK3fpxITk1iSjam/A404ZYqBr//AGWv9hdZM1nP5bo3bO\n" + 
				"HULWoA7DSz3mxOqRb72KI/CGmB9tDKH+Nw5JiArT/Y/V5lS4HzyoMP+6HD0JoKa7\n" + 
				"e7IfVlwoKVdUY//02mj9zMn4zjiBvzFjAJQx5QqgtOc61e5P6uO5MilLsx5rsu/U\n" + 
				"B8bsJR0LFhSrwF+D79o5ht4Yh15yzztX+peJ3kjfSE8ileLAvH1QhtFgk7AdA5Yf\n" + 
				"BTmWKI6OIKNucqGqsAMJ+zTN4WO2yFAgZpQgdNQ3TxaWqCvOzNXbttgaprAgQln/\n" + 
				"H7gzbKf65rhhavEpFOsaPq3WXqJcwMMkLJAbbNS21Fjd+OrYSoJ3VScfQ5uQxbe1\n" + 
				"O4Nv0aXOGXuTN23559Hn9uWoF11hOvrSK/Ceu6Rr76and/waa9mbbKVwfnifmL1A\n" + 
				"OaD3mijfEtfd4FRyo7rEPqHzrMXwUsiUF364iOJ1SFQdUzhL/SEA04wfWkWcyxYo\n" + 
				"ydKGJzDBtnng0Fe7kKqqK8LK/v9FrFu+IxSeE9wJurKQ39vN5V2Jz6ybfAwTkxx3\n" + 
				"22TqINaPxPmchQV75FdljIEp/u8cfXJtgCI053MKbPq0QRS0lSskIxqqqyanrNUZ\n" + 
				"1YaJuH4u5PiVNcHKpJOsPzdnepHc88KitkkyWcXEPiwUzUPZhWcS5b289UbBs7P9\n" + 
				"b+zQciMvwq8iHJyHtNRcxLyIuclUOw4zpwJ2ztGGOCQI9KctsFxGj6WVXHgOfbn5\n" + 
				"0yXvQN6JBE8rzd1DBtNhjA0XIgxgrdYhXnrsr+HCOzvAcmCrpMo8y9xbJkOK1drp\n" + 
				"QTeKuto6sCjopjh9vqQ/T7oIxecA5IAzKKJd4XOb05iyK8YPejQ47tCFcBGG/xP7\n" + 
				"-----END RSA PRIVATE KEY-----";
		
		p = "Welcome123";
		
	}
	
	@Test 
	public void cloneX500NameNoOrganizationIdentifier() {
		
		 String subjectDN = "C=US,O=NASA,SERIALNUMBER=13+CN=Dwight Eisenhower";
		 String organizationIdentifier = "PSDES-BDE-3DFD21";
		 		 
		 X500Name subjectDnBefore = new X500Name( subjectDN );
		 
		 
		 EiDASCertificate eidascert = new EiDASCertificate();
		 
		 X500Name subjectDnAfter = eidascert.replaceOrganizationIdentifier( subjectDnBefore, organizationIdentifier);
		 
		 String subjectDnStringAfter = subjectDnAfter.toString();
		 
		 
		 assertEquals( subjectDnStringAfter, "C=US,O=NASA,SERIALNUMBER=13+CN=Dwight Eisenhower,2.5.4.97=PSDES-BDE-3DFD21" );

	}
	
	
	@Test
	public void addFullSetOfRolesNoOrgId() {

		String orgId = null;
	    String ncaName = "Auth";
	    String ncaId = "Germany";
	    
		List<String> roles = new ArrayList<String>(Arrays.asList( "PSP_AS", "PSP_PI", "PSP_AI", "PSP_IC" )); 
			    
		

		EiDASCertificate eidascert = new EiDASCertificate();

		String certpem = eidascert.addPsdAttibutes( c, k, p, orgId, ncaName, ncaId, roles );
		
	
		assertEquals( certpem,
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIIECDCCAvCgAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADCBlDELMAkGA1UEBhMC\n" + 
				"REUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\n" + 
				"DAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\n" + 
				"Q0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\n" + 
				"MTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjB6MRMwEQYDVQQDDApkb21haW5OYW1l\n" + 
				"MQwwCgYDVQQKDANvcmcxCzAJBgNVBAsMAm91MRAwDgYDVQQGEwdHZXJtYW55MQ8w\n" + 
				"DQYDVQQIDAZCYXllcm4xEjAQBgNVBAcMCU51cmVtYmVyZzERMA8GA1UEYQwIMTIz\n" + 
				"NDU5ODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzezfS9BIdspq9\n" + 
				"wa4oxGo+aMxBVYOxLR4h/9X4hU/8fnxgq7BIrVKbgeckcjPcRhr+ULeJmkemQJnh\n" + 
				"wLqlmdAtcmbhU16dKnIAYV9YhIe3HEr1s7LUeKt2qEMyXXQvz9RGFOkceqDqGqSR\n" + 
				"GwBlRMOmPTvVsVYyzqhSh4SiLFWOO3U4ZZy47ymgSgVvRE+Vg8A3YWkS/605LU6p\n" + 
				"0IIA1PPg7ym3/8fZ6C8UTXuFIoXn+ukOGiEE9tGHqSr4IrlNtb3fMbRWW/pR109D\n" + 
				"uNLAqFByjYzR+unbWZ0qCgwVnddIcupGehmnEcNkx8hTLAbdYk4b16cy7RWxoSj0\n" + 
				"FahPt59zAgMBAAGjezB5MHcGCCsGAQUFBwEDBGswaTBnBgYEAIGYJwIwXTBMMBEG\n" + 
				"BwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkwEQYHBACBmCcBAwwG\n" + 
				"UFNQX0FJMBEGBwQAgZgnAQQMBlBTUF9JQwwEQXV0aAwHR2VybWFueTANBgkqhkiG\n" + 
				"9w0BAQUFAAOCAQEAfq57JDdlX9btYBfFl4GLY9mHCBrXV0O4H9DDVJYl+RjO3B3q\n" + 
				"uzU5SUtWzdOnAvJ28wLe0hvN6oxX/DxD5S/oLP51PFfsygkArxDurbSz2RsfsbcO\n" + 
				"4mXtw1ChuktKWm/E3u2U0IHDR6KDaT3pr8jlDv5mJnJmTi7hIM3xnz38rn9ok1Qs\n" + 
				"wTF5vEINaluFOXoSfB4VB+TPro1Tdh6mlS0d01iiUKK/kmIaCTlFMFSCsvW9GqQw\n" + 
				"KQ0MeAhgrccabZr8+VzbdfMVygHGpiB77yqsYztTSjspPaxltmv5i3IUDUC3MZTK\n" + 
				"y3m/0/+q+LL+vZsQYpPIREUWa/2cDYiwKFXRxQ==\n" + 
				"-----END CERTIFICATE-----\n" );
	}


	@Test
	public void addSingleRoleWithOrdId() {

	    String orgId = "PSDES-BDE-3DFD21";
	    String ncaName = "CA";
	    String ncaId = "Britain";
	    
		List<String> roles = new ArrayList<String>(Arrays.asList( "PSP_AS" )); 
			    
		

		EiDASCertificate eidascert = new EiDASCertificate();

		String certpem = eidascert.addPsdAttibutes( c, k, p, orgId, ncaName, ncaId, roles );
		
	
		assertEquals( certpem,
				"-----BEGIN CERTIFICATE-----\n" + 
				"MIID1jCCAr6gAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADCBlDELMAkGA1UEBhMC\n" + 
				"REUxDzANBgNVBAgMBkhlc3NlbjESMBAGA1UEBwwJRnJhbmtmdXJ0MRUwEwYDVQQK\n" + 
				"DAxBdXRob3JpdHkgQ0ExCzAJBgNVBAsMAklUMSEwHwYDVQQDDBhBdXRob3JpdHkg\n" + 
				"Q0EgRG9tYWluIE5hbWUxGTAXBgkqhkiG9w0BCQEWCmNhQHRlc3QuZGUwHhcNMTgx\n" + 
				"MTEzMDk0MjU4WhcNMTgxMTMwMTAyMzI3WjCBgjETMBEGA1UEAwwKZG9tYWluTmFt\n" + 
				"ZTEMMAoGA1UECgwDb3JnMQswCQYDVQQLDAJvdTEQMA4GA1UEBhMHR2VybWFueTEP\n" + 
				"MA0GA1UECAwGQmF5ZXJuMRIwEAYDVQQHDAlOdXJlbWJlcmcxGTAXBgNVBGEMEFBT\n" + 
				"REVTLUJERS0zREZEMjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz\n" + 
				"ezfS9BIdspq9wa4oxGo+aMxBVYOxLR4h/9X4hU/8fnxgq7BIrVKbgeckcjPcRhr+\n" + 
				"ULeJmkemQJnhwLqlmdAtcmbhU16dKnIAYV9YhIe3HEr1s7LUeKt2qEMyXXQvz9RG\n" + 
				"FOkceqDqGqSRGwBlRMOmPTvVsVYyzqhSh4SiLFWOO3U4ZZy47ymgSgVvRE+Vg8A3\n" + 
				"YWkS/605LU6p0IIA1PPg7ym3/8fZ6C8UTXuFIoXn+ukOGiEE9tGHqSr4IrlNtb3f\n" + 
				"MbRWW/pR109DuNLAqFByjYzR+unbWZ0qCgwVnddIcupGehmnEcNkx8hTLAbdYk4b\n" + 
				"16cy7RWxoSj0FahPt59zAgMBAAGjQDA+MDwGCCsGAQUFBwEDBDAwLjAsBgYEAIGY\n" + 
				"JwIwIjATMBEGBwQAgZgnAQEMBlBTUF9BUwwCQ0EMB0JyaXRhaW4wDQYJKoZIhvcN\n" + 
				"AQEFBQADggEBABbJAOs7JqXQL4ovxSEwaB08prhq8x+9SAK5e4IF1Mn+CHfafCAS\n" + 
				"ZttYMb2nDt9DSoUNWW5Mzn1DBkTA4LEZtIfM547SeyOjKNkiQTVSS83It58Ou0vc\n" + 
				"nAXU7xTLKbbK+U5MuGetfsGdiNjCgzY32besNTEQ2JcOeVxs5wZF8+/bgf6d2xNl\n" + 
				"smXRoqsavNnzolhmxNzackdOKVn1FmAMwdBxC/cH4DpNCdXFteCYRuxEs453sYZJ\n" + 
				"BkaFceu0XrUTTW2+eqWWgkv8ZqOLyq8W22tdDCv0ndvAiAGhfKmDh4WJvIBIJAL5\n" + 
				"x1IS754+1mJmR3KCMzpUo0PueEdhARFqrVs=\n" + 
				"-----END CERTIFICATE-----\n" );
	}
	
	@Test
	public void createCertficateFromJson() {
				
		
		String json = "" +
			"{\n" + 
			"  \"certInfo\": {\n" + 
			"    \"basicConstraints\": \"CA: true\",\n" + 
			"    \"subject\": \"OID.2.5.4.97\\u003d12345987, L\\u003dNuremberg, ST\\u003dBayern, C\\u003dGermany, OU\\u003dou, O\\u003dorg, CN\\u003ddomainName\",\n" + 
			"    \"issuer\": \"EMAILADDRESS\\u003dca@test.de, CN\\u003dAuthority CA Domain Name, OU\\u003dIT, O\\u003dAuthority CA, L\\u003dFrankfurt, ST\\u003dHessen, C\\u003dDE\",\n" + 
			"    \"validFrom\": 1543573407000,\n" + 
			"    \"expiryDate\": 1543573407000,\n" + 
			"    \"isValid\": \"\\u003cTODO\\u003e\",\n" + 
			"    \"publicKey\": \"RSA, 2048\",\n" + 
			"    \"serialNumber\": 1875022970,\n" + 
			"    \"sigAlgName\": \"SHA1withRSA\",\n" + 
			"    \"version\": 3,\n" + 
			"    \"fingerprintSha256\": \"8345ed6b67056bb641e6ccac5a0579acdf80663de59f7b92f561b66bb6d8876b\",\n" + 
			"    \"fingerprintSha1\": \"cc1adb500568facbff32b475161936dc5becfc4b\",\n" + 
			"    \"ncaName\": \"ncaname\",\n" + 
			"    \"ncaId\": \"ncaid\",\n" + 
			"    \"rolesOfPSP\": [\"PSP_AS\",\"PSP_PI\"]\n" + 
			"  }\n" + 
			"}";
		
		
		
		EiDASCertificate eidascert = new EiDASCertificate();
		String keyPem = null;
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			byte[] privateKeyEncoded = 	new byte[]{
			 48, -126, 4, -67, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4,
			 -126, 4, -89, 48, -126, 4, -93, 2, 1, 0, 2, -126, 1, 1, 0, -97, -123, -111, -113, -93,
			 -53, 39, 80, 49, 22, 17, -31, 56, -95, -88, -18, -98, -47, -18, -38, -128, 93, 16, 26,
			 -54, -32, 65, 45, 19, -124, 43, 123, -125, 38, 29, 123, -21, 35, -53, -50, 124, -101,
			 -120, 59, 39, 58, -108, -122, 114, 48, -111, 34, -83, -121, -8, -62, 2, -47, -73, -58,
			 -120, -108, -36, 40, 125, -9, -117, -16, 113, 38, -60, -61, 55, -83, 77, -64, 110, 110,
			 102, -7, -44, -107, 10, -110, -84, 33, 99, 70, -57, -111, -3, -13, 68, 112, -61, -108,
			 126, -19, 126, 117, 71, -109, 112, 23, 86, 123, 13, 62, -34, 28, 74, 37, -88, 117, 32,
			 -110, -81, 109, -55, 71, 8, -46, -15, 118, 39, 99, 104, -101, 112, 40, 123, 85, 118,
			 -123, 14, -23, 118, 94, 21, -68, 111, 90, 121, 118, -113, 72, -118, -86, -70, -51,
			 86, 25, 62, 57, 88, 83, 90, 84, 115, -5, -96, -68, 114, 43, 126, 107, -83, -98, -40,
			 90, 125, -117, 107, 33, 106, -18, -54, -74, -7, 48, 35, 8, -127, -123, 25, 2, -40, 62,
			 27, 82, 18, -38, -77, -40, -95, 69, 41, -27, 67, -13, -112, -12, -105, 119, 29, -100,
			 -51, -85, -124, 50, 113, 108, 60, -128, -42, -87, 103, -47, 6, -7, 47, 17, 20, 67, 65,
			 -1, -79, 108, -101, 78, -22, -4, -41, 63, 119, -103, -108, -108, -58, -100, -36, 87,
			 -86, 33, -46, 78, 104, 51, 22, 76, -116, 125, -65, 80, -1, 67, 2, 3, 1, 0, 1, 2, -126,
			 1, 0, 25, 116, -20, -54, 65, -26, -55, 34, -52, 122, -117, -90, -25, -19, 48, 114, -56,
			 8, -109, 119, -18, 21, 43, -35, 66, -77, -17, -30, -68, 35, 18, -9, 86, 114, 14, 49, 120,
			 -48, 81, 21, 102, 32, 65, -24, -62, -75, 95, -1, 102, -104, -90, -120, -92, -83, -74, -66,
			 107, 73, -63, 108, -98, -34, 54, -106, 5, -88, 43, -2, 86, 104, 75, -19, 37, 100, -12, 43,
			 -7, -45, -121, 126, 101, -12, -44, -25, -100, 45, -123, -44, -59, 67, 96, -123, -30, 77,
			 -90, -128, 123, -110, -11, -29, -52, 100, -44, 117, -4, -8, -115, 32, 19, -68, -22, -2,
			 64, 120, 84, -106, -28, 4, -2, -94, 101, -33, -105, -27, -11, -102, 49, 22, -96, -101, 66,
			 49, -125, -120, -107, -45, -108, 63, -111, 45, -22, 105, 11, -121, 109, 80, 73, -70, 75, 3,
			 -55, 116, -98, -3, 20, -119, -100, -74, 80, -32, 72, -105, 31, -120, -113, 113, 40, -41, 50,
			 5, -105, -78, -18, 52, -3, 50, -40, 124, -93, -124, -42, 7, 39, -15, 85, 96, 34, 114, -93, -4,
			 -68, 12, -127, -49, -67, 95, 30, -100, -59, 124, -85, -6, -109, -26, -6, -37, 55, -6, -79, 23,
			 121, -64, -35, 21, 102, 12, -44, -126, 91, 31, 126, -80, 78, 56, 61, -92, 42, 32, -113, 42, 1,
			 -60, 63, 23, 52, -102, 42, 14, -16, 120, -63, 48, -81, 78, -51, -70, -24, -122, -32, 51, -43,
			 -113, 96, -25, 42, 17, 2, -127, -127, 0, -54, -96, -4, 54, -6, 123, -39, 20, 61, 10, -75, 112,
			 124, -14, 121, -28, 112, 7, 28, -126, 125, 25, 69, -119, -81, 62, 43, 11, -40, -75, 36, 43, 101,
			 36, 54, -104, -95, 83, -4, 110, 109, -115, 7, 96, -101, 45, 27, -15, 44, -39, 107, 62, -36, -116,
			 -86, -76, -58, 115, -67, 42, -42, 45, -117, -60, -87, -24, -71, -73, 80, 115, 68, 22, 125, 53,
			 -114, -78, 94, -111, 117, -99, 53, 16, -12, 52, -36, 90, -115, -40, -94, -59, -24, 110, -86, -59,
			 -106, 101, -21, -26, -103, -85, 102, 39, -128, -4, -79, 46, -60, 5, 11, -3, 93, 73, -95, -22, -48,
			 -65, -31, -53, 19, 75, 20, -53, 72, -11, -17, -46, -25, 81, 2, -127, -127, 0, -55, -119, -20, -68,
			 92, 48, 37, 62, -56, 60, 50, -110, -97, -62, 29, 76, -75, 10, -91, -16, -100, 9, -40, -10, 65, -115,
			 -93, 119, 21, -71, -12, 30, 21, -67, -1, -81, 59, -32, -122, 85, 13, 43, 24, 122, 112, -55, 121,
			 -110, -35, 104, -15, 76, 78, -122, 93, -128, -90, -20, 19, -115, -53, 119, -108, 98, 64, -24, 114,
			 82, 85, 15, 115, 39, -87, 89, 9, -31, -128, 80, -70, -29, 4, -64, 81, 3, 118, 94, 110, -39, 38,
			 -32, 81, 26, 121, -121, -109, 12, -123, 62, -113, -61, 109, -113, -86, -111, 9, 34, 63, 77, 86, 20,
			 69, 124, 41, -56, 38, -88, -80, -4, -6, -62, -100, 79, 26, 65, -126, -16, 0, 83, 2, -127, -127, 0,
			 -61, -4, -44, 22, -27, 78, 55, 24, 113, 54, 83, 106, 123, 32, 25, 48, 15, -1, -128, -34, -31, -37,
			 56, -68, 68, -55, 47, -33, -92, 123, 8, -126, 4, -80, -13, 49, -52, 17, 44, -1, 46, 109, 19, 46,
			 -88, -55, 7, -42, -51, 87, 122, 120, -15, -32, 9, 25, 19, 62, 77, 65, 10, -86, 65, 31, 54, 108,
			 -120, 125, 59, -114, 81, -44, 34, -59, 83, -63, 72, -31, 14, -50, -64, -50, 38, 54, -98, -49, -29,
			 -107, 31, 83, -89, 78, -85, 84, -77, -12, -33, 40, 75, -120, 82, 37, 113, -120, 120, 100, 80, 106,
			 -59, 63, 10, 37, 55, 60, -91, 46, -125, 89, -27, -50, 96, 77, -125, -61, -123, 117, 12, 17, 2, -127,
			 -128, 90, -6, -63, 124, -14, -100, -27, 99, 103, 31, 13, -79, 117, 31, 58, -4, -46, -55, -128, -55,
			 -110, -105, 59, 115, 71, 122, 122, 45, -101, 8, 59, -12, -116, -38, 29, -97, 108, -121, 89, -4, -15,
			 25, -32, 77, -3, -74, 102, 4, 111, -95, 29, 52, -42, 73, -1, -47, -63, 8, -41, 118, -18, 64, 8, 35,
			 38, -84, 8, 87, -76, -128, 105, -6, -96, -113, 74, 79, -101, 14, 86, -97, 127, 24, -106, 57, -38,
			 -24, -100, 95, -71, 22, 16, 102, -60, 47, -8, -88, -15, 73, -95, -70, -106, 46, 1, -48, -63, 111,
			 -51, 101, -53, 19, 17, -97, 16, 121, -125, 66, 41, -53, -70, 35, -70, 78, 87, 74, -11, -94, 4, 115,
			 2, -127, -128, 86, 123, 106, 70, 71, -102, 65, -31, -36, -70, 42, 41, -29, 60, 90, 17, -33, 75, -36,
			 -80, -22, -108, 118, 115, -7, 107, -49, 51, 63, 103, 90, 65, 61, -41, 31, -36, -98, 107, 14, 118,
			 -26, 48, -4, 84, 104, -82, -117, 45, -15, -13, -85, 52, 44, -101, -17, -97, -127, -51, 120, -83, -94,
			 -57, -58, 110, -13, -99, 33, 74, -43, 104, -71, -24, -20, 64, -54, 52, -52, -24, -42, 110, 0, -87, 97,
			 105, 56, -5, 37, 118, -119, 11, -63, 38, 38, -14, 86, 93, 40, 30, -6, -79, -65, -99, 21, 9, -78, 83, 64,
			 -4, 104, 66, -113, -128, 107, -47, 20, 45, -108, -79, -37, -42, 35, 24, -1, 123, 53, -62, 82, 116};

			byte[] publicKeyEncoded = 	new byte[]{
48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48,
			          -126, 1, 10, 2, -126, 1, 1, 0, -97, -123, -111, -113, -93, -53, 39, 80, 49, 22, 17, -31, 56, -95,
			          -88, -18, -98, -47, -18, -38, -128, 93, 16, 26, -54, -32, 65, 45, 19, -124, 43, 123, -125, 38, 29,
			          123, -21, 35, -53, -50, 124, -101, -120, 59, 39, 58, -108, -122, 114, 48, -111, 34, -83, -121, -8,
			          -62, 2, -47, -73, -58, -120, -108, -36, 40, 125, -9, -117, -16, 113, 38, -60, -61, 55, -83, 77,
			          -64, 110, 110, 102, -7, -44, -107, 10, -110, -84, 33, 99, 70, -57, -111, -3, -13, 68, 112, -61,
			          -108, 126, -19, 126, 117, 71, -109, 112, 23, 86, 123, 13, 62, -34, 28, 74, 37, -88, 117, 32, -110,
			          -81, 109, -55, 71, 8, -46, -15, 118, 39, 99, 104, -101, 112, 40, 123, 85, 118, -123, 14, -23, 118,
			          94, 21, -68, 111, 90, 121, 118, -113, 72, -118, -86, -70, -51, 86, 25, 62, 57, 88, 83, 90, 84, 115,
			          -5, -96, -68, 114, 43, 126, 107, -83, -98, -40, 90, 125, -117, 107, 33, 106, -18, -54, -74, -7, 48,
			          35, 8, -127, -123, 25, 2, -40, 62, 27, 82, 18, -38, -77, -40, -95, 69, 41, -27, 67, -13, -112, -12,
			          -105, 119, 29, -100, -51, -85, -124, 50, 113, 108, 60, -128, -42, -87, 103, -47, 6, -7, 47, 17, 20,
			          67, 65, -1, -79, 108, -101, 78, -22, -4, -41, 63, 119, -103, -108, -108, -58, -100, -36, 87, -86,
			          33, -46, 78, 104, 51, 22, 76, -116, 125, -65, 80, -1, 67, 2, 3, 1, 0, 1};
			
			 PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
		       
			 
			 KeyFactory rsaKF = KeyFactory.getInstance("RSA", "BC");
			 PrivateKey privateKey = rsaKF.generatePrivate(pkcs8EncodedKeySpec);
					 
			 
			 
			 X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
		        PublicKey publicKey = rsaKF.generatePublic(x509EncodedKeySpec);	 
					 
			
			KeyPair keyPair = new KeyPair(publicKey, privateKey);
			
			keyPem = eidascert.privateKeyPem( keyPair, "Welcome123" );
			
			
			X509Certificate cert = eidascert.createFromJson(json, keyPair);
			
			
			
			pem = eidascert.writePem( cert );
			
			
		} catch (IOException e) {
			
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		} catch (NoSuchProviderException e) {

			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
		
		
assertEquals(keyPem, "-----BEGIN RSA PRIVATE KEY-----\n" + 
		"Proc-Type: 4,ENCRYPTED\n" + 
		"DEK-Info: AES-256-CBC,6E33E339CE0BB6B1B78ECB5172F6BE48\n" + 
		"\n" + 
		"EAuLeVfd7evM6TqCr0k2nrzlwtBnwA9cOvpq8OvgAGNsoLPLr9PnS+kzeMDQ2J3V\n" + 
		"QmhiCNmCdOxXbqEwPw1PBEGs36ItdE1dMoZR0l0RymNa0vZKYni7hltjjz+f4m4H\n" + 
		"E0VnGCkat4RuFCVMxoWvjwTLe1HeK1Oo1ik79wYX3a7wHszCybGVLHTKMtpP2MCn\n" + 
		"+xC1Zt+Vd8wmvvnC5iTaJpvbJMne+NgR0+xMyrsed3oBNzdtrfoS4vGsk3cLvrvn\n" + 
		"fIeQcUg1aHlfgcHBjUW9RUS/0nuvwdjjRNYr+/29EhOrcZemDS3YcVZGSVf/e/x9\n" + 
		"opjE6SjeBfaj6D+isaN3N6jvlhZqI09cR6Kz6epPlIrj6rjZrFR2XHGdlVBxxUZb\n" + 
		"YteMHpmWZDIfrjIB3zMSozNor9rRXXZ3yeFX3FSmxo5EUjHinm8xMSlTNv1/XHCJ\n" + 
		"YfZ2nYvBDHfgddqAqVfE9gAwnf/GCCk+wUftn58CngauNGK5KEJEqTXLzRrW0L6z\n" + 
		"yrNpb4m1g457F5jOAOo8aPesXhqN3lo+/xFVs6taUchFBOuq3FCOL36xVW/xCdqD\n" + 
		"yQEjP9PUE0/rJMf183+mxyuFx2/ABNAmtBxbNv4uz1pxcn1f33skHtEQN1PkFx/1\n" + 
		"HvtQQfvVWjQOiJxuy3FtDWYPvBVczgbPX3MuX9kPTBW4gFrwprqDLjgvkarj5Jrx\n" + 
		"91gs9Zf+lSp3UusTuR7vClsCqAtceIWmBIKez4WLTE3nZPNAa8G2yJfylVMaK0do\n" + 
		"OQjX7chKIgpCnd73O4D9ZwSupscoykkeuNF9JLyC1DkSzGvsbwbYqairO07i8FRz\n" + 
		"LEa+apcoT5nh2DnK4G03e4HU1o49LL9xinqCckgU1FuqsRku+eJuRxPT7ietSv9r\n" + 
		"3mh5O/7Pk1NNJCzx9JgiOgeFVKVIB8trP3OCWkyR6bVLIbABqKh0apXlmkIkHqUy\n" + 
		"n4kLpTgPVVWvt/7Pn5NLCQh6h/fnCvfBwa8QuE+EQsAeJNiRZCa/Rg0eilN4Lr5X\n" + 
		"vMd0LM48aSfLi36ExmgyGCu2D+Dlsj7DQGxY3BT+kokgzFvLAS+c/aA8/zIdYuGy\n" + 
		"jC2hrKrH0QEoVjCKpsBboWP73tfSWmoKBpMfVcngH5E53n6NbOP5DOud948HZzY7\n" + 
		"arnMg95seYMV5z9brwQuLGAfBZ0VHFqVqsQ0dMHqWawJFSTRkHRRGBSgpvUHaoKQ\n" + 
		"fH0tlBKKaGa39c/h/BE2oovNHCbWC1ZUiio2yMcCOfKLJj8+7pEGax38E6JAOOgW\n" + 
		"yqD2ou8s9H4Qsf+MjG1k2oVGUd/TZADM/8KnhHe9vDoLOYYkLGV0nKl12TCrHqgE\n" + 
		"mZEx+P6XsCilOd2cek1PXXpz7LZ1wsHg/ewLhk/hmzrAEkBdE4OEdZizg92HDWZk\n" + 
		"pXktw4nr6uzf3TAmEUnEnjSlHjnWNrQcRXKdHTzx2ndDJNXPk8BQTnzGWMHppHu4\n" + 
		"PARqy36yrUcKTtftBOX/+eix0L55wwJ8IirZESPFEo159TFzagZt5i5+4S6aVSYm\n" + 
		"zipAyJsXbWO5/Kn6EpVqsoM0rKWckjKM7G/+lThBFEwqI4LzNJIIsgDVdhHbvGsP\n" + 
		"-----END RSA PRIVATE KEY-----\n" );
		
	}
	
}
