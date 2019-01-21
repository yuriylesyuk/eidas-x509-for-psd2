package com.exco.eidas;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.IETFUtils;
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
}
