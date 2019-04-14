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
import java.util.stream.Collectors;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class EiDASCertificateTest {

	String c;
	String k;
	String p;
	
	@Before
	public void testSetup() {
		
		
		
		
		c = "-----BEGIN CERTIFICATE-----\n" 
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
				+ "Q1q2Ca1AIXrpFAoDBAvqtQb4lyPnG6BJcwYBUg==\n"
				+ "-----END CERTIFICATE-----";
		
		k = "-----BEGIN RSA PRIVATE KEY-----\n" + 
				"Proc-Type: 4,ENCRYPTED\n" + 
				"DEK-Info: AES-256-CBC,CEB76431E65244905C479719951EBC9F\n" + 
				"\n" + 
				"Hzg6p4bRR7Vk/Re/8R/zpvA9pFaJ/TG2UXhsax/cjvsgfs49zpCDyfczhEcOSpyA" + 
				"wycYYlXj4StGKybOfYbUn8H50pWvMi/7m+UL0lUw9Z5BrNlr8p/8FQPYTdOdEkv8" + 
				"WNtSQcpZSSyZCDi18Gqshz44Y2HZrWqnO0ODV/dQ60DP1nWh+vGNNVC93fY7FQWb" + 
				"J17qdPL9FcX6Frm7To0528WUjY1VnwbNxeNOEeNDHRwGJRFQcwXfCa++2cMjOx2q" + 
				"qBvHBShcutd07hDiu2Y4pIPfAOCGcletNXLfZGgNCdHOT6uzY4BrVYmLGje2tYay" + 
				"NcOMuDY0pZOKlsbCJ+pT+hXxf9s7Kh7SFBX+EgkdcgGR0Yf+US8LQ8RFoE6m8O+/" + 
				"G/wls6IgdbWd2+oXx208SPgecWu9NwtnjT9FbCFedPuq/YXwz+WtmtkpsixpPQSJ" + 
				"PujE1l9qWUFDqe4crKVgnoiYjQEEihWm0HWrw/PKA2qBDJdi37MjJeWw2N+NdgAF" + 
				"rUM32juUnZiaejKMOnterZWwENAjY6EhfLM7hx2pecU548C+x2T6uIRfNQsKHWk9" + 
				"B4qftnjZbX7efygIRLUGWJF/4tnmx7lHq0cZyRV3E8k6b5b7GSSfnYuRZzjliiUd" + 
				"euUq2EzsMWPA6eQBK63j2+aXRyVep8SMINIkj/Usx6NJadbFl2h7hvAVk62ThfZ5" + 
				"YXctzniwrbFVuuaty8vbK3fpxITk1iSjam/A404ZYqBr//AGWv9hdZM1nP5bo3bO" + 
				"HULWoA7DSz3mxOqRb72KI/CGmB9tDKH+Nw5JiArT/Y/V5lS4HzyoMP+6HD0JoKa7" + 
				"e7IfVlwoKVdUY//02mj9zMn4zjiBvzFjAJQx5QqgtOc61e5P6uO5MilLsx5rsu/U" + 
				"B8bsJR0LFhSrwF+D79o5ht4Yh15yzztX+peJ3kjfSE8ileLAvH1QhtFgk7AdA5Yf" + 
				"BTmWKI6OIKNucqGqsAMJ+zTN4WO2yFAgZpQgdNQ3TxaWqCvOzNXbttgaprAgQln/" + 
				"H7gzbKf65rhhavEpFOsaPq3WXqJcwMMkLJAbbNS21Fjd+OrYSoJ3VScfQ5uQxbe1" + 
				"O4Nv0aXOGXuTN23559Hn9uWoF11hOvrSK/Ceu6Rr76and/waa9mbbKVwfnifmL1A" + 
				"OaD3mijfEtfd4FRyo7rEPqHzrMXwUsiUF364iOJ1SFQdUzhL/SEA04wfWkWcyxYo" + 
				"ydKGJzDBtnng0Fe7kKqqK8LK/v9FrFu+IxSeE9wJurKQ39vN5V2Jz6ybfAwTkxx3" + 
				"22TqINaPxPmchQV75FdljIEp/u8cfXJtgCI053MKbPq0QRS0lSskIxqqqyanrNUZ" + 
				"1YaJuH4u5PiVNcHKpJOsPzdnepHc88KitkkyWcXEPiwUzUPZhWcS5b289UbBs7P9" + 
				"b+zQciMvwq8iHJyHtNRcxLyIuclUOw4zpwJ2ztGGOCQI9KctsFxGj6WVXHgOfbn5" + 
				"0yXvQN6JBE8rzd1DBtNhjA0XIgxgrdYhXnrsr+HCOzvAcmCrpMo8y9xbJkOK1drp" + 
				"QTeKuto6sCjopjh9vqQ/T7oIxecA5IAzKKJd4XOb05iyK8YPejQ47tCFcBGG/xP7\n" + 
				"-----END RSA PRIVATE KEY-----\n";
		
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
			"{" + 
			"  \"certInfo\": {" + 
			"    \"basicConstraints\": \"CA: true\"," + 
			"    \"subject\": \"OID.2.5.4.97\\u003d12345987, L\\u003dNuremberg, ST\\u003dBayern, C\\u003dGermany, OU\\u003dou, O\\u003dorg, CN\\u003ddomainName\"," + 
			"    \"issuer\": \"EMAILADDRESS\\u003dca@test.de, CN\\u003dAuthority CA Domain Name, OU\\u003dIT, O\\u003dAuthority CA, L\\u003dFrankfurt, ST\\u003dHessen, C\\u003dDE\"," + 
			"    \"validFrom\": 1543573407000," + 
			"    \"expiryDate\": 1543573407000," + 
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
			
			
			// Password [Welcome123] is removed so we generate same key result consistently to make job easier for JUnit test.
			keyPem = eidascert.privateKeyPem( keyPair, null );
			
			
			X509Certificate cert = eidascert.createCertificateFromJson(json, keyPair.getPrivate(), keyPair.getPublic() );
			
			
			
			pem = eidascert.writeCertPem( cert );
			
			
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
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfhZGPo8snUDEW\n" + 
		"EeE4oajuntHu2oBdEBrK4EEtE4Qre4MmHXvrI8vOfJuIOyc6lIZyMJEirYf4wgLR\n" + 
		"t8aIlNwoffeL8HEmxMM3rU3Abm5m+dSVCpKsIWNGx5H980Rww5R+7X51R5NwF1Z7\n" + 
		"DT7eHEolqHUgkq9tyUcI0vF2J2Nom3Aoe1V2hQ7pdl4VvG9aeXaPSIqqus1WGT45\n" + 
		"WFNaVHP7oLxyK35rrZ7YWn2LayFq7sq2+TAjCIGFGQLYPhtSEtqz2KFFKeVD85D0\n" + 
		"l3cdnM2rhDJxbDyA1qln0Qb5LxEUQ0H/sWybTur81z93mZSUxpzcV6oh0k5oMxZM\n" + 
		"jH2/UP9DAgMBAAECggEAGXTsykHmySLMeoum5+0wcsgIk3fuFSvdQrPv4rwjEvdW\n" + 
		"cg4xeNBRFWYgQejCtV//ZpimiKSttr5rScFsnt42lgWoK/5WaEvtJWT0K/nTh35l\n" + 
		"9NTnnC2F1MVDYIXiTaaAe5L148xk1HX8+I0gE7zq/kB4VJbkBP6iZd+X5fWaMRag\n" + 
		"m0Ixg4iV05Q/kS3qaQuHbVBJuksDyXSe/RSJnLZQ4EiXH4iPcSjXMgWXsu40/TLY\n" + 
		"fKOE1gcn8VVgInKj/LwMgc+9Xx6cxXyr+pPm+ts3+rEXecDdFWYM1IJbH36wTjg9\n" + 
		"pCogjyoBxD8XNJoqDvB4wTCvTs266IbgM9WPYOcqEQKBgQDKoPw2+nvZFD0KtXB8\n" + 
		"8nnkcAccgn0ZRYmvPisL2LUkK2UkNpihU/xubY0HYJstG/Es2Ws+3IyqtMZzvSrW\n" + 
		"LYvEqei5t1BzRBZ9NY6yXpF1nTUQ9DTcWo3YosXobqrFlmXr5pmrZieA/LEuxAUL\n" + 
		"/V1JoerQv+HLE0sUy0j179LnUQKBgQDJiey8XDAlPsg8MpKfwh1MtQql8JwJ2PZB\n" + 
		"jaN3Fbn0HhW9/6874IZVDSsYenDJeZLdaPFMToZdgKbsE43Ld5RiQOhyUlUPcyep\n" + 
		"WQnhgFC64wTAUQN2Xm7ZJuBRGnmHkwyFPo/DbY+qkQkiP01WFEV8KcgmqLD8+sKc\n" + 
		"TxpBgvAAUwKBgQDD/NQW5U43GHE2U2p7IBkwD/+A3uHbOLxEyS/fpHsIggSw8zHM\n" + 
		"ESz/Lm0TLqjJB9bNV3p48eAJGRM+TUEKqkEfNmyIfTuOUdQixVPBSOEOzsDOJjae\n" + 
		"z+OVH1OnTqtUs/TfKEuIUiVxiHhkUGrFPwolNzylLoNZ5c5gTYPDhXUMEQKBgFr6\n" + 
		"wXzynOVjZx8NsXUfOvzSyYDJkpc7c0d6ei2bCDv0jNodn2yHWfzxGeBN/bZmBG+h\n" + 
		"HTTWSf/RwQjXdu5ACCMmrAhXtIBp+qCPSk+bDlaffxiWOdronF+5FhBmxC/4qPFJ\n" + 
		"obqWLgHQwW/NZcsTEZ8QeYNCKcu6I7pOV0r1ogRzAoGAVntqRkeaQeHcuiop4zxa\n" + 
		"Ed9L3LDqlHZz+WvPMz9nWkE91x/cnmsOduYw/FRorost8fOrNCyb75+BzXitosfG\n" + 
		"bvOdIUrVaLno7EDKNMzo1m4AqWFpOPsldokLwSYm8lZdKB76sb+dFQmyU0D8aEKP\n" + 
		"gGvRFC2UsdvWIxj/ezXCUnQ=\n" + 
		"-----END RSA PRIVATE KEY-----\n" );
		
	}
	
	
	@Test
	public void createCSRFromJson() {
				
		
		String json = "" +
			"{" + 
			"  \"certInfo\": {" + 
			"    \"basicConstraints\": \"CA: true\"," + 
			"    \"subject\": \"OID.2.5.4.97\\u003d12345987, L\\u003dNuremberg, ST\\u003dBayern, C\\u003dGermany, OU\\u003dou, O\\u003dorg, CN\\u003ddomainName\"," + 
			"    \"issuer\": \"EMAILADDRESS\\u003dca@test.de, CN\\u003dAuthority CA Domain Name, OU\\u003dIT, O\\u003dAuthority CA, L\\u003dFrankfurt, ST\\u003dHessen, C\\u003dDE\"," + 
			"    \"validFrom\": 1543573407000," + 
			"    \"expiryDate\": 1543573407000," + 
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
			"}";
		
		
		
		EiDASCertificate eidascert = new EiDASCertificate();
		String keyPem = null;
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			
			KeyPair keyPair = eidascert.genKeyPair();
			
			keyPem = eidascert.privateKeyPem( keyPair, null );
			
			PKCS10CertificationRequest csr = eidascert.createCertificationRequestFromJson(json, keyPair);
			

			pem = eidascert.writeCSRPem( csr );
			
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}

	}
	
	@Test
	public void createCSRWithKUandEKUFromJson() {
				
		
		String json = "" +
			"{" +
			"  \"certInfo\": {" + 
			"    \"basicConstraints\": \"CA: true\"," + 
			"    \"subject\": \"OID.2.5.4.97\\u003d12345987, L\\u003dNuremberg, ST\\u003dBayern, C\\u003dGermany, OU\\u003dou, O\\u003dorg, CN\\u003ddomainName\"," + 
			"    \"issuer\": \"EMAILADDRESS\\u003dca@test.de, CN\\u003dAuthority CA Domain Name, OU\\u003dIT, O\\u003dAuthority CA, L\\u003dFrankfurt, ST\\u003dHessen, C\\u003dDE\"," + 
			"    \"validFrom\": 1543573407000," + 
			"    \"expiryDate\": 1543573407000," + 
			"    \"isValid\": \"\\u003cTODO\\u003e\"," + 
			"    \"publicKey\": \"RSA, 2048\"," + 
			"    \"serialNumber\": 1875022970," + 
			"    \"sigAlgName\": \"SHA1withRSA\"," + 
			"    \"version\": 3," + 
			"    \"keyUsage\": [\"digitalSignature\",\"keyCertSign\"]," + 
			"    \"extKeyUsage\": [\"serverAuth\",\"clientAuth\"]," + 
			"    \"qcTypes\": [\"eSeal\",\"eWeb\"]," + 
			"    \"ncaName\": \"ncaname\"," + 
			"    \"ncaId\": \"ncaid\"," + 
			"    \"rolesOfPSP\": [\"PSP_AS\",\"PSP_PI\"]" + 
			"  }" + 
			"}";
		
		
		
		EiDASCertificate eidascert = new EiDASCertificate();
		String keyPem = null;
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			
			KeyPair keyPair = eidascert.genKeyPair();
			
			keyPem = eidascert.privateKeyPem( keyPair, null );
			
			PKCS10CertificationRequest csr = eidascert.createCertificationRequestFromJson(json, keyPair);
			

			pem = eidascert.writeCSRPem( csr );
			
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}

	}
	
	
	
	@Test
	public void signCSRFromJson() {
				
		
		String json = "" +
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
			"}";
		
		// intermediate_ca.pem 
		String imcaKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" + 
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
				"-----END RSA PRIVATE KEY-----";
	
		
		String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + 
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
				"-----END CERTIFICATE REQUEST-----";
		
		EiDASCertificate eidascert = new EiDASCertificate();
		
		PrivateKey imcaPrivateKey = null;
		PublicKey csrPublicKey = null;
		
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			
			imcaPrivateKey = eidascert.getKeyPair( imcaKeyPem, null ).getPrivate();
			
			
			csrPublicKey = eidascert.getPublicKeyFromCSRPem( csrPem );
			
			
			
			X509Certificate cert = eidascert.createCertificateFromJson( json, imcaPrivateKey, csrPublicKey ); 
			
			
			pem = eidascert.writeCertPem( cert );
			
			assertEquals( pem, "-----BEGIN CERTIFICATE-----\n" + 
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
					"-----END CERTIFICATE-----\n" ); 

					
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	
	
	@Test
	public void signCSRWithKUandEKUFromJson() {
				
		
		String json = "" +
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
			"    \"keyUsage\": [\"digitalSignature\",\"keyCertSign\"]," + 
			"    \"extKeyUsage\": [\"serverAuth\",\"clientAuth\"]," + 
			"    \"ncaName\": \"ncaname\"," + 
			"    \"ncaId\": \"ncaid\"," + 
			"    \"rolesOfPSP\": [\"PSP_AS\",\"PSP_PI\"]" + 
			"  }" + 
			"}";
		
		// intermediate_ca.pem 
		String imcaKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" + 
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
				"-----END RSA PRIVATE KEY-----";
	
		
		String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + 
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
				"-----END CERTIFICATE REQUEST-----";
		
		EiDASCertificate eidascert = new EiDASCertificate();
		
		PrivateKey imcaPrivateKey = null;
		PublicKey csrPublicKey = null;
		
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			
			imcaPrivateKey = eidascert.getKeyPair( imcaKeyPem, null ).getPrivate();
			
			
			csrPublicKey = eidascert.getPublicKeyFromCSRPem( csrPem );
			
			
			
			X509Certificate cert = eidascert.createCertificateFromJson( json, imcaPrivateKey, csrPublicKey ); 
			
			
			pem = eidascert.writeCertPem( cert );
			
			assertEquals( pem, "-----BEGIN CERTIFICATE-----\n" + 
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
					"-----END CERTIFICATE-----\n" ); 

					
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	

	
	@Test
	public void signCSRWithAIAandCRLDPsFromJson() {
				
		
		String json = "" +
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
			"	 \"aia\": {\n" + 
			"	     \"caIssuers\": \"http://www.exco.com/ca.cer\",\n" + 
			"	     \"ocsp\": \"http://ocsp.exco.com\"\n" + 
			"	 }," +
			"    \"crlDPs\": [" +
			"         \"http://crl.exco.com/master.crl\"," +
			"         \"ldap://crl.somewebsite.com/cn%3dSecureCA%2cou%3dPKI%2co%3dCyberdyne%2cc%3dUS?certificaterevocationlist;binary\"" +
			"    ]," + 
			"    \"version\": 3" + 
			"  }" + 
			"}";
		
		// intermediate_ca.pem 
		String imcaKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n" + 
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
				"-----END RSA PRIVATE KEY-----";
	
		
		String csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n" + 
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
				"-----END CERTIFICATE REQUEST-----";
		
		EiDASCertificate eidascert = new EiDASCertificate();
		
		PrivateKey imcaPrivateKey = null;
		PublicKey csrPublicKey = null;
		
		String pem = null;
		
		Security.addProvider(new BouncyCastleProvider());

		try {
			
			imcaPrivateKey = eidascert.getKeyPair( imcaKeyPem, null ).getPrivate();
			
			
			csrPublicKey = eidascert.getPublicKeyFromCSRPem( csrPem );
			
			
			
			X509Certificate cert = eidascert.createCertificateFromJson( json, imcaPrivateKey, csrPublicKey ); 
			
			
			pem = eidascert.writeCertPem( cert );
			
			assertEquals( 
					"-----BEGIN CERTIFICATE-----\n" + 
					"MIIEwTCCA6mgAwIBAgIEb8KUejANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJV\n" + 
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
					"YrMiqaom5aXm3p0ovOAJ3HT0twIDAQABo4IBJTCCASEwDAYDVR0TBAUwAwEB/zAO\n" + 
					"BggrBgEFBQcBAwQCMAAwWAYIKwYBBQUHAQEETDBKMCYGCCsGAQUFBzAChhpodHRw\n" + 
					"Oi8vd3d3LmV4Y28uY29tL2NhLmNlcjAgBggrBgEFBQcwAYYUaHR0cDovL29jc3Au\n" + 
					"ZXhjby5jb20wgaYGA1UdHwSBnjCBmzAkoCKgIIYeaHR0cDovL2NybC5leGNvLmNv\n" + 
					"bS9tYXN0ZXIuY3JsMHOgcaBvhm1sZGFwOi8vY3JsLnNvbWV3ZWJzaXRlLmNvbS9j\n" + 
					"biUzZFNlY3VyZUNBJTJjb3UlM2RQS0klMmNvJTNkQ3liZXJkeW5lJTJjYyUzZFVT\n" + 
					"P2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3Q7YmluYXJ5MA0GCSqGSIb3DQEBBQUA\n" + 
					"A4IBAQBpKAdjVRj40oBDyuuVvMmfOUEapSKCHzwjJJ66oVgKBr4VyMbB3W8NAJfk\n" + 
					"/2HryN3tF4PRP/kaES+jaL0umz+OUAvXGIVO7ByUVowskpPuiSHlZ8zndQnYKVua\n" + 
					"QQ9UqN0uF3pgvjpqW6wOcIaOYgp1tMmVP1izvzruH19akk7nNXqCsnR3HUyup/jL\n" + 
					"lqjzFdh3nzdRFHWOZNqcDaAUPfMfWNojH06wyzLqN2PBNB1dlN0+YybRR6pfXBH1\n" + 
					"PUT56mV6AjEesn/swlxm8mONgaQR1iHWmgeObioxqGUarxMX1lm4UtlivcMoBBB1\n" + 
					"BmViTPQlImphsp66T+vQv5WTL+ip\n" + 
					"-----END CERTIFICATE-----\n"
					, pem
				); 

					
		} catch (IOException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	
	@Test
	public void testKeyUsage() {
		
		// https://www.ibm.com/support/knowledgecenter/SSKTMJ_9.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html
		
		//
		// Roundtrip for EKUs
		EiDASCertificate eidascert = new EiDASCertificate();

		String json = 
				  "{\n" + 
				  "	\"keyUsage\": [\n" + 
				  "		\"digitalSignature\",\n" + 
				  "		\"keyCertSign\"\n" + 
				  "	]\n" + 
				  "}";
		
		JsonObject jsonObject = (new JsonParser()).parse( json ).getAsJsonObject();
		JsonArray jsonArray = jsonObject.getAsJsonArray("keyUsage");
		
		KeyUsage kus = new KeyUsage( eidascert.getKeyUsagesFromJson( jsonArray ) );
		
		JsonArray jsonArrayAfter = eidascert.getKeyUsageToJsonArray( kus );
		
		assertEquals( jsonArray, jsonArrayAfter );
		
		// 0, 5
		boolean[] kusbits = new boolean[9];
		kusbits[ 0 ] = true;
		kusbits[ 5 ] = true;		
		
		JsonArray jsonArrayBitNames = eidascert.getKeyUsageToJsonArray( kusbits );
		
		assertEquals( jsonArray, jsonArrayBitNames );
	}


	@Test
	public void testExtendedKeyUsage() {
		
		// https://www.ibm.com/support/knowledgecenter/SSKTMJ_9.0.1/admin/conf_keyusageextensionsandextendedkeyusage_r.html
		
		//
		// Roundtrip for EKUs
		EiDASCertificate eidascert = new EiDASCertificate();

		String json = 
				  "{\n" + 
				  "	\"extKeyUsage\": [\n" + 
				  "		\"serverAuth\",\n" + 
				  "		\"clientAuth\"\n" + 
				  "	]\n" + 
				  "}";
		JsonObject jsonObject = (new JsonParser()).parse( json ).getAsJsonObject();
		JsonArray jsonArray = jsonObject.getAsJsonArray("extKeyUsage");
		
		List<KeyPurposeId> kps = eidascert.getExtKeyUsageFromJsonArray( jsonArray );
		
		JsonArray jsonArrayAfter = eidascert.getExtendedKeyUsageToJsonArray( kps );
		
		assertEquals( jsonArray, jsonArrayAfter);
		
		List<String> kpstrs = kps.stream().map( oid -> oid.toString()).collect(Collectors.toList() );
		
		List<KeyPurposeId> kpsoids =  (List<KeyPurposeId>)eidascert.convertStringToKeyPurposeIdList( kpstrs );
		
		assertEquals( kps, kpsoids );
		
	}
	
}




