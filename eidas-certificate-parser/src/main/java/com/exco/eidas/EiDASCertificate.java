package com.exco.eidas;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import com.google.common.hash.Hashing;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

public class EiDASCertificate {
	
	public static final ASN1ObjectIdentifier oid_QCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");

	
    public static final ASN1ObjectIdentifier oid_etsi_qcs_QcType = new ASN1ObjectIdentifier("0.4.0.1862.1.6");

    public static final ASN1ObjectIdentifier oid_etsi_qcs_QcType_eSign = oid_etsi_qcs_QcType.branch("1");
    public static final ASN1ObjectIdentifier oid_etsi_qcs_QcType_eSeal = oid_etsi_qcs_QcType.branch("2");
    public static final ASN1ObjectIdentifier oid_etsi_qcs_QcType_eWeb = oid_etsi_qcs_QcType.branch("3");
	
	
    public static final ASN1ObjectIdentifier oid_etsi_psd2_qcStatement = new ASN1ObjectIdentifier( "0.4.0.19495.2" );
    
    public static final ASN1ObjectIdentifier oid_etsi_psd2_roles = new ASN1ObjectIdentifier( "0.4.0.19495.1" );
    
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_as = oid_etsi_psd2_roles.branch("1");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_pi = oid_etsi_psd2_roles.branch("2");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_ai = oid_etsi_psd2_roles.branch("3");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_ic = oid_etsi_psd2_roles.branch("4");
    
    
    
    // QcTypes
    public static final Map<String,ASN1ObjectIdentifier> qcTypesOids = new LinkedHashMap<String,ASN1ObjectIdentifier>() {{
        put( "eSign", oid_etsi_qcs_QcType_eSign );
        put( "eSeal", oid_etsi_qcs_QcType_eSeal );
        put( "eWeb", oid_etsi_qcs_QcType_eWeb );
    }};
    
    public static final Map<ASN1ObjectIdentifier,String> qcTypesNames = new LinkedHashMap<ASN1ObjectIdentifier,String>() {{
        put( oid_etsi_qcs_QcType_eSign, "eSign"  );
        put( oid_etsi_qcs_QcType_eSeal, "eSeal" );
        put( oid_etsi_qcs_QcType_eWeb, "eWeb" );
    }};

    
    // not in BC 1.56 which Edge uses
    public static final ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER =  new ASN1ObjectIdentifier("2.5.4.97").intern();
    
    private static final Hashtable<ASN1ObjectIdentifier,String> OverrideSymbols = new Hashtable();
    static
    {
    	OverrideSymbols.put( ORGANIZATION_IDENTIFIER, "organizationIdentifier");
    }

    private static final Hashtable<String,ASN1ObjectIdentifier> LookUpSymbols = new Hashtable();
    static
    {
    	LookUpSymbols.put( "organizationIdentifier", ORGANIZATION_IDENTIFIER );
    }

    public static final Map<String,ASN1ObjectIdentifier> rolesOids = new LinkedHashMap<String,ASN1ObjectIdentifier>() {{
        put( "PSP_AS", oid_etsi_psd2_role_psp_as );
        put( "PSP_PI", oid_etsi_psd2_role_psp_pi );
        put( "PSP_AI", oid_etsi_psd2_role_psp_ai );
        put( "PSP_IC", oid_etsi_psd2_role_psp_ic );
    }};
    
    
	public X509Certificate getCertificate(String pemCertificate) {
		
		ByteArrayInputStream inputStream = new ByteArrayInputStream(pemCertificate.getBytes());

		CertificateFactory certFactory;
		
		X509Certificate cert = null;

		try {
			certFactory = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) certFactory.generateCertificate(inputStream);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
		}

		return cert;
	}
	

	private String getPkDescription(PublicKey pk) {
		int length = 0;

		if (pk instanceof RSAPublicKey) {

			length = ((RSAPublicKey) pk).getModulus().bitLength();

		} else if (pk instanceof DSAPublicKey) {

			length = ((DSAPublicKey) pk).getParams().getP().bitLength();

		} else if (pk instanceof ECPublicKey) {

			length = ((ECPublicKey) pk).getParams().getCurve().getField().getFieldSize();

		} else if (pk instanceof JCEECPublicKey) {
			length = -1;
		}

		return pk.getAlgorithm() + ", " + (length != -1 ? String.valueOf(length) : "Unknown key class");
	}

	private List<String> getSubjectDNAsList(X500Principal subject ) {
		
		X500Name name = new X500Name( subject.getName(X500Principal.RFC1779) );
		
		
		
		List<String> list = new ArrayList<String>();
		
		RDN[] rdns = name.getRDNs();
		for( RDN rdn : rdns) {
			AttributeTypeAndValue[] atvs =  rdn.getTypesAndValues();
			for( AttributeTypeAndValue atv : atvs ) {
				
				String displayType = OverrideSymbols.get( atv.getType() );
				if( displayType == null) {
					displayType = BCStyle.INSTANCE.oidToDisplayName( atv.getType() );
					if( displayType == null) {
						displayType = atv.getType().getId();
					}
				}  
				
				
			   list.add( displayType + "=" + atv.getValue() );
			}
			
			
		}
		
		return list;
	}
	
	protected String replaceOverrides( String rdnsString ) {
		
 		String replacedRdnsString = rdnsString;
		
		for( String dn : LookUpSymbols.keySet() ) {
			replacedRdnsString = replacedRdnsString.replaceAll( dn+"=", LookUpSymbols.get(dn).getId().toString()+"=" );
		};
		
		return replacedRdnsString;
	}
	
	protected X500Name replaceOrganizationIdentifier( X500Name name, String organizationIdentifier ) {

		
		boolean isReplaced = false;
		
		 RDN[] rdns = name.getRDNs();
		 X500NameBuilder namebuilder = null; 
		 
		 namebuilder = new X500NameBuilder();
		 
		 for( RDN rdn : rdns) {
			 
			 if( rdn.isMultiValued() ) {
				 List<AttributeTypeAndValue> atvs = new ArrayList<AttributeTypeAndValue>();
				 for( AttributeTypeAndValue matv : rdn.getTypesAndValues() ) {
					 if( matv.getType().equals(  ORGANIZATION_IDENTIFIER ) ) {
						 atvs.add( new AttributeTypeAndValue ( ORGANIZATION_IDENTIFIER, new DERUTF8String( organizationIdentifier ) ) );
						 isReplaced = true;
					 }else {
					 	atvs.add( matv );
					 }
				 }
				 namebuilder.addMultiValuedRDN( atvs.toArray(new AttributeTypeAndValue[0] ) );
			 } else {
				 AttributeTypeAndValue atv = rdn.getFirst();
				 if( atv.getType().equals(  ORGANIZATION_IDENTIFIER ) ) {
					 namebuilder.addRDN( new AttributeTypeAndValue(  ORGANIZATION_IDENTIFIER, new DERUTF8String( organizationIdentifier ) ) );
					 isReplaced = true;
				 }else {
					 namebuilder.addRDN( atv );
				 }
			 }
		 }
		 
		if( !isReplaced ) {
			 
			namebuilder.addRDN( new AttributeTypeAndValue(  ORGANIZATION_IDENTIFIER, new DERUTF8String( organizationIdentifier ) ) ); 
		}		
		
		return namebuilder.build();
	}
	



	public String showPemAsJSON( X509Certificate cert ) {
		

		Date expiryDate = cert.getNotAfter();
		Date validFromDate = cert.getNotBefore();

		Date now = new Date();

		// TODO: certificate validity

		JsonObject certAttributes = new JsonObject();
		// ifnull
		// certAttributes.addProperty("keyUsage", cert.getKeyUsage());

		// getKeyUsage
		certAttributes.addProperty("basicConstraints",
				cert.getBasicConstraints() == -1 ? "CA: false" : "CA: true");

		certAttributes.addProperty("subject", String.join(", ", getSubjectDNAsList( cert.getSubjectX500Principal() ) ) );
				
		certAttributes.addProperty("issuer", cert.getIssuerDN().toString());

		certAttributes.addProperty("validFrom", expiryDate.getTime());
		certAttributes.addProperty("expiryDate", expiryDate.getTime());
		certAttributes.addProperty("isValid", "<TODO>");

		certAttributes.addProperty("publicKey", getPkDescription(cert.getPublicKey()));

		certAttributes.addProperty("serialNumber", cert.getSerialNumber());

		certAttributes.addProperty("sigAlgName", cert.getSigAlgName());

		certAttributes.addProperty("version", cert.getVersion());

		JsonObject certObject = new JsonObject();
		certObject.add("certInfo", certAttributes);
		try {

			// Calculate fingerprints: sha1/sha256
			String fingerprintSha256 = Hashing.sha256().hashBytes(cert.getEncoded()).toString();
			certAttributes.addProperty("fingerprintSha256", fingerprintSha256);
	
			String fingerprintSha1 = Hashing.sha1().hashBytes(cert.getEncoded()).toString();
			certAttributes.addProperty("fingerprintSha1", fingerprintSha1);
	
			// keyUsage:
			boolean[] keyUsage = cert.getKeyUsage();
			if( keyUsage != null ) {
				JsonArray keyUsageJsonArray = getKeyUsageToJsonArray( keyUsage );
				certAttributes.add( "keyUsage", keyUsageJsonArray );
			}
			
		    // extentedKeyUsage:
			List<String> extKeyUsage = cert.getExtendedKeyUsage();
			if( extKeyUsage != null ) {
				JsonArray ekus = getExtendedKeyUsageToJsonArray( 
						convertStringToKeyPurposeIdList( extKeyUsage )
					);
				certAttributes.add( "extKeyUsage", ekus );
			}
			
			
			// qcExtentions: qcType
			String qcTypes = getQcRoles( cert );
			if( qcTypes != null ){
				certAttributes.addProperty( "qcTypes", qcTypes );
			}
			
			// qcExtentions: psd2
			Map<String,Object> attrs = getNcaAndRolesOfPSP(cert);
			if( attrs != null ) {
				certAttributes.addProperty("ncaName", (String)attrs.get("ncaname"));
				certAttributes.addProperty("ncaId", (String)attrs.get("ncaid"));
				certAttributes.add("rolesOfPSP", (JsonArray)attrs.get("roles") );
			}


		} catch (Exception e) {

			throw new RuntimeException( e );
		}

		Gson gson =new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
	
		return gson.toJson(certObject);
	}
	
	
	
	public String writeCertPem( X509Certificate cert ) {
	
		StringWriter sw = new StringWriter();
	
		try (PemWriter pw = new PemWriter(sw)) {
			
			PemObjectGenerator gen;
			gen = new JcaMiscPEMGenerator(cert);
			pw.writeObject(gen);
		  
		} catch (IOException e) {

			e.printStackTrace();
		}
	
		return sw.toString();
		
	
	}
	
	private String getQcRoles( X509Certificate cert ) throws Exception {
		
		List<String> typesList = null;
		String typesJson = null;
		
		byte[] extv = cert.getExtensionValue(Extension.qCStatements.getId());
		ASN1OctetString akiOc = ASN1OctetString.getInstance(extv);

		ASN1Sequence qcStatements;

		// try{
		qcStatements = (ASN1Sequence) new ASN1InputStream(akiOc.getOctets()).readObject();

		for (int i = 0; i < qcStatements.size(); i++) {
			final QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(i));

			if (oid_etsi_qcs_QcType.getId().equals(qcStatement.getStatementId().getId())) {

				typesList = new ArrayList<String>();
				
				ASN1Encodable statementInfo = qcStatement.getStatementInfo();
	
				ASN1Sequence types = ASN1Sequence.getInstance(statementInfo);
				
				//
				for (int t = 0; t < types.size(); t++) {
	
					ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance( types.getObjectAt(t) );
	
					typesList.add( qcTypesNames.get( oid ) );
				}
				
				typesJson = "[" + typesList.stream().map(t -> "\"" + t + "\"").reduce((ts, t) -> ts + "," + t).get() + "]"; 
				
			}
		}
		// }catch(){}
		
		return typesJson;
	}
	
	private Map<String,Object> getNcaAndRolesOfPSP( X509Certificate cert ) throws Exception {

		Map<String,Object> attrs =null;
		

		byte[] extv = cert.getExtensionValue(Extension.qCStatements.getId());
		ASN1OctetString akiOc = ASN1OctetString.getInstance(extv);

		ASN1Sequence qcStatements = null;;

		// try{
		qcStatements = (ASN1Sequence) new ASN1InputStream(akiOc.getOctets()).readObject();

		for (int i = 0; i < qcStatements.size(); i++) {
			final QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(i));

			if (oid_etsi_psd2_qcStatement.getId().equals(qcStatement.getStatementId().getId())) {
				
				String ncaName = null;
				String ncaId = null;
				JsonArray rolesList = new JsonArray();
				

				ASN1Encodable statementInfo = qcStatement.getStatementInfo();
	
				ASN1Sequence psd2QcType = ASN1Sequence.getInstance(statementInfo);
	
				ASN1Sequence roles = ASN1Sequence.getInstance(psd2QcType.getObjectAt(0));
				DERUTF8String derNCAName = DERUTF8String.getInstance(psd2QcType.getObjectAt(1));
				DERUTF8String derNCAId = DERUTF8String.getInstance(psd2QcType.getObjectAt(2));
				
				ncaName = derNCAName.getString();
				ncaId = derNCAId.getString();
				//
	
				for (int r = 0; r < roles.size(); r++) {
	
					ASN1Sequence role = ASN1Sequence.getInstance(roles.getObjectAt(r));
	
					ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(role.getObjectAt(0));
					DERUTF8String roleOfPSPName = DERUTF8String.getInstance(role.getObjectAt(1));
	
					rolesList.add( new JsonPrimitive( roleOfPSPName.getString() ) );
	
				}
				
				
				attrs = new HashMap<String,Object>();
				attrs.put( "ncaname", ncaName );
				attrs.put( "ncaid", ncaId );
				attrs.put("roles", rolesList );
				
			}
		}

		return attrs;
	}
	
	private void setRolesOfPSP(X509Certificate cert, String[] roles ) throws Exception {
		
		byte[] extv = cert.getExtensionValue(Extension.qCStatements.getId());
		ASN1OctetString akiOc = ASN1OctetString.getInstance(extv);

		ASN1Sequence qcStatements;

		// try{
		qcStatements = (ASN1Sequence) new ASN1InputStream(akiOc.getOctets()).readObject();

		// iterate through qcStatement to find current psd2 roles statement, if not, append a new one
		int psd2QcStat = -1;
		for (int i = 0; i < qcStatements.size(); i++) {
			final QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(i));

			if (!oid_etsi_psd2_qcStatement.getId().equals(qcStatement.getStatementId().getId())) {
				// panic if not a psd2 roles statement
				psd2QcStat = i;
				break;

			}
			
		}
		
		if( psd2QcStat == -1 ) {
			// clone 
		   QCStatement[] newQcStatements = new QCStatement[ qcStatements.size()+1 ];
		   for (int i = 0; i < qcStatements.size(); i++) {
			   newQcStatements[i] = QCStatement.getInstance( qcStatements.getObjectAt(i) );
		   }
		   
		   // append a new one
		   newQcStatements[ newQcStatements.length -1 ] = new QCStatement( oid_etsi_psd2_qcStatement );
		   
		}
		
		// psd2 roles statemet 
		// a) clear
		
		
		
		// b) set if required
		
		///
		///
		
	}

	protected KeyPair getKeyPair( String pemRSAPrivateKey, String password) {
		
		
		BufferedReader br = new BufferedReader( new InputStreamReader( new ByteArrayInputStream( pemRSAPrivateKey.getBytes() ) ) );
		
		
		try{
			
			final PEMParser parser = new PEMParser(br);
			 
			 
			final Object privateKeyPemObject = parser.readObject();
			 
			final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			
			
			final KeyPair keyPair;
			
			if( privateKeyPemObject instanceof PEMEncryptedKeyPair ) {
				
				final PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) privateKeyPemObject;
	            final PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
	                    .build( password.toCharArray() );
	            
	            keyPair = converter.getKeyPair(ckp.decryptKeyPair(decProv));
			}else {
				keyPair = converter.getKeyPair((PEMKeyPair) privateKeyPemObject);
			}

			
			return keyPair;
			
		} catch (PEMException e) {
			throw new RuntimeException( e );
		
		} catch (IOException e) {
				throw new RuntimeException( e );
		}
			 
	}
	
	
	public PublicKey getPublicKeyFromCSRPem( String csrPem ) throws IOException {
		
		PublicKey rsaPublicKey = null;
		PemReader reader = null;
		
		try{ 
			reader = new PemReader( new BufferedReader( new InputStreamReader( new ByteArrayInputStream( csrPem.getBytes() ) ) ) );
			
			final PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reader.readPemObject().getContent());
			
			SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
			RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);
			
			RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			rsaPublicKey = kf.generatePublic(rsaSpec);
			
		}catch(FileNotFoundException e) {
			throw new RuntimeException( e );
		} catch (IOException e) {
			throw new RuntimeException( e );
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException( e );
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException( e );
		}finally {
			reader.close();
		}
		
	    return rsaPublicKey;
	}
	
	
	private QCStatement qcStatementForRoles( 
			String ncaName,
			String ncaId,
			List<String> rolesList) {
		
	    final ASN1EncodableVector roles = new ASN1EncodableVector();
	    
	    for( String roleKey : rolesList ) {
	    	
	    	final ASN1EncodableVector role = new ASN1EncodableVector();
	    	
	    	role.add( rolesOids.get( roleKey ) );
	    	role.add( new DERUTF8String( roleKey ));
	    	
	    	roles.add(new DERSequence( role ));
	    }

	    ASN1Encodable st = new DERSequence(new ASN1Encodable[]{
	    		new DERSequence(roles ), 
	    		new DERUTF8String( ncaName ), 
	    		new DERUTF8String( ncaId ) 
	    	});
	    
	    return new QCStatement(oid_etsi_psd2_qcStatement, st);
	}
	
	
	private QCStatement qcStatementForQcType(
				List<String> typesList 
			) {
		
	    final ASN1EncodableVector types = new ASN1EncodableVector();
		
	    for( String typeKey : typesList ) {
	    	
	    	final ASN1EncodableVector type = new ASN1EncodableVector();
	    	
	    	types.add( qcTypesOids.get( typeKey ) );
	    }
		
	    DERSequence typesDS = new DERSequence( types );
	    
		return new QCStatement(oid_etsi_qcs_QcType, typesDS );
	}

	//
	// Key Usage
	//
    // https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.02.01_60/ts_119495v010201p.pdf	
	private Map<String,Integer> keyUsagesOids = new LinkedHashMap<String,Integer>() {{
        put( "digitalSignature", KeyUsage.digitalSignature );
        put( "nonRepudiation", KeyUsage.nonRepudiation );
        put( "keyEncipherment", KeyUsage.keyEncipherment );
        put( "dataEncipherment", KeyUsage.dataEncipherment );
        put( "keyAgreement", KeyUsage.keyAgreement );
        put( "keyCertSign", KeyUsage.keyCertSign );
        put( "cRLSign", KeyUsage.cRLSign );
        put( "encipherOnly", KeyUsage.encipherOnly );
        put( "decipherOnly", KeyUsage.decipherOnly );
    }};
    
	private Map<Integer,String> keyUsagesNames = new LinkedHashMap<Integer,String>() {{
        put( KeyUsage.digitalSignature, "digitalSignature" );
        put( KeyUsage.nonRepudiation, "nonRepudiation" );
        put( KeyUsage.keyEncipherment, "keyEncipherment" );
        put( KeyUsage.dataEncipherment, "dataEncipherment" );
        put( KeyUsage.keyAgreement, "keyAgreement" );
        put( KeyUsage.keyCertSign, "keyCertSign" );
        put( KeyUsage.cRLSign, "cRLSign" );
        put( KeyUsage.encipherOnly, "encipherOnly" );
        put( KeyUsage.decipherOnly, "decipherOnly" );
    }};

	private Map<Integer,String> keyUsagesBitNames = new LinkedHashMap<Integer,String>() {{
        put( 0, "digitalSignature" );
        put( 1, "nonRepudiation" );
        put( 2, "keyEncipherment" );
        put( 3, "dataEncipherment" );
        put( 4, "keyAgreement" );
        put( 5, "keyCertSign" );
        put( 6, "cRLSign" );
        put( 7, "encipherOnly" );
        put( 8, "decipherOnly" );
    }};
    
    protected int getKeyUsagesFromJson( JsonArray kusJson ) {
    	
    	int kus = 0;
    	for( JsonElement ku : kusJson) {
			String kuidName = ku.getAsString();
			Integer kuid = keyUsagesOids.get( kuidName );
			if( kuid == null ) {
				throw new RuntimeException(
						String.format( "EIDAS: Not supported Key Usage Id: %s", kuidName )
				);
			}else {
				kus |= kuid;
			}
		}
    	
    	
    	return kus;
    }

	protected JsonArray getKeyUsageToJsonArray( KeyUsage kus ) {
		
		JsonArray ja = new JsonArray();
		
		for (Map.Entry<Integer, String> ku : keyUsagesNames.entrySet()) {
			if( kus.hasUsages( ku.getKey() ) ){
				
				JsonPrimitive kuJsonString = new JsonPrimitive( ku.getValue() );
				ja.add( kuJsonString );
			}
		}

		
		return ja;
	}


	protected JsonArray getKeyUsageToJsonArray( boolean[] kus ) {
		
		JsonArray ja = new JsonArray();
		
		for( int i = 0; i < kus.length; i++ ) {
			if(kus[i] ) {
				JsonPrimitive kuJsonString = new JsonPrimitive( keyUsagesBitNames.get(i) );
				ja.add( kuJsonString );
			}
		}
		
		return ja;
	}
	
	//
	// Extended Key Usage
	//
    // https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.02.01_60/ts_119495v010201p.pdf	
	private Map<String,KeyPurposeId> keyPurposeIds = new LinkedHashMap<String,KeyPurposeId>() {{
        put( "codeSigning", KeyPurposeId.id_kp_codeSigning );
        put( "serverAuth", KeyPurposeId.id_kp_serverAuth );
        put( "clientAuth", KeyPurposeId.id_kp_clientAuth );
        put( "emailProtection", KeyPurposeId.id_kp_emailProtection );
    }};
    
	private Map<KeyPurposeId,String> keyPurposeIdsNames = new LinkedHashMap<KeyPurposeId,String>() {{
        put( KeyPurposeId.id_kp_codeSigning, "codeSigning" );
        put( KeyPurposeId.id_kp_serverAuth, "serverAuth" );
        put( KeyPurposeId.id_kp_clientAuth, "clientAuth" );
        put( KeyPurposeId.id_kp_emailProtection, "emailProtection" );
    }};
	
    
    
    
	//	
    protected List<KeyPurposeId> getExtKeyUsageFromJsonArray( JsonArray ekusJson ) {

		List<KeyPurposeId> ekus = null;
		
		for( JsonElement eku : ekusJson) {
			if( ekus == null) {
				ekus = new ArrayList<KeyPurposeId>();
			}
			String ekuidName = eku.getAsString();
			KeyPurposeId ekuid = keyPurposeIds.get( ekuidName );
			if( ekuid == null ) {
				throw new RuntimeException(
						String.format( "EIDAS: Not supported Key Purpose Id: %s", ekuidName )
				);
			}else {
				ekus.add( ekuid );
			}
		}
				
		return ekus;
	}
	
    protected List<KeyPurposeId> convertStringToKeyPurposeIdList( List<String> kpids ){
    	
    	return kpids.stream().map( 
    			s -> KeyPurposeId.getInstance( new ASN1ObjectIdentifier( s ) )
    	).collect( Collectors.toList() );
    }
    
	protected JsonArray getExtendedKeyUsageToJsonArray( List<KeyPurposeId> ekus ) {
		
		JsonArray ja = new JsonArray();
		
		for( KeyPurposeId eku : ekus ){
			String ekuName = keyPurposeIdsNames.get( eku );
			if( ekuName == null ){
						throw new RuntimeException(
								String.format( "EIDAS: Unknowen Key Purpose Name: %s", ekuName )
						);
			}else{
				
				JsonPrimitive ekuJsonString = new JsonPrimitive( ekuName );
				ja.add( ekuJsonString );
			}
		}

		
		return ja;
	}

	
	// TODO: refactor with XREF:createCertificateFromJson
	// XXXXXXXXXXX

	public PKCS10CertificationRequest createCertificationRequestFromJson(
			String json, 
			KeyPair keyPair
	) throws OperatorCreationException, IOException {
		
		/// C&P section:
		JsonObject certdesc = (new JsonParser()).parse( json ).getAsJsonObject();
		
		JsonObject certinfo = certdesc.getAsJsonObject("certInfo");
	
		
	 
		
		String issuerDN = certinfo.get("issuer").getAsString();
		String subjectDN = certinfo.get("subject").getAsString();
		
		long notBefore = certinfo.get("validFrom").getAsLong() / 1000L;;
		long notAfter = certinfo.get("expiryDate").getAsLong() / 1000L;;

		BigInteger serialNumber = certinfo.get("serialNumber").getAsBigInteger();
		/// C&P section: EOS
		
	
	
		
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Name( replaceOverrides( subjectDN ) ), 
		    	keyPair.getPublic()
		);
		
		/// C&P section: BOS
		ExtensionsGenerator extensionGenerator = new ExtensionsGenerator();
		
				
		// Key Usage 
		JsonElement keyUsageJsonElement = certinfo.get("keyUsage");
		if( keyUsageJsonElement != null ) {
			int kus = getKeyUsagesFromJson( keyUsageJsonElement.getAsJsonArray() );
			if( kus != 0 ) {
				extensionGenerator.addExtension(Extension.keyUsage,true, new KeyUsage( kus) );
			}
		}
		
		// Extended Key Usage
		JsonElement extKeyUsageJsonElement = certinfo.get("extKeyUsage");
		if( extKeyUsageJsonElement != null ) {
			List<KeyPurposeId> keyPurposeIds =  getExtKeyUsageFromJsonArray( extKeyUsageJsonElement.getAsJsonArray() );
				extensionGenerator.addExtension(
						Extension.extendedKeyUsage, true,
			            new ExtendedKeyUsage( keyPurposeIds.toArray( new KeyPurposeId[0] ) )
			);
		}
		
		// QcStatements collector
	    final ASN1EncodableVector qcsts = new ASN1EncodableVector();

	    /// QcTypes Statement 
		List<String> typesList = new ArrayList<String>();

		JsonElement types = certinfo.get("qcTypes");
		if( types != null ) {
			for( JsonElement t: types.getAsJsonArray() ) {
				typesList.add( t.getAsString() );
			}
	
			QCStatement qcTypeSt = qcStatementForQcType( typesList );
		    qcsts.add( qcTypeSt );
		}
	    
		/// C&P section, psd2 attributes:
		String ncaName = certinfo.get("ncaName").getAsString();
		String ncaId =  certinfo.get("ncaId").getAsString();
		
		
		List<String> rolesList = new ArrayList<String>();
		
		JsonArray roles = certinfo.get("rolesOfPSP").getAsJsonArray();
		for( JsonElement r: roles) {
			rolesList.add( r.getAsString() );
		}

	    QCStatement qcPsd2St = qcStatementForRoles( ncaName, ncaId, rolesList );
	    
	    qcsts.add( qcPsd2St );
	    
	    
		
		extensionGenerator.addExtension(oid_QCStatements, false,
				new DERSequence( qcsts ) 
		);
		
		p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionGenerator.generate());

		
		
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		
		ContentSigner signer = csBuilder.build( keyPair.getPrivate() );

		
		
		
		
		PKCS10CertificationRequest csr = p10Builder.build(signer);
		
		return csr;
	}

	
	
	// TODO: refactor with writePem
	// XXXXXXXXXXX
	public String writeCSRPem( PKCS10CertificationRequest csr) {

		/// C&P section, sw, pw:

	    StringWriter sw = null;
	    
	    try( PemWriter pw = new JcaPEMWriter( sw = new StringWriter()) ) {
	    	
	    	PemObjectGenerator gen;
	    	gen = new JcaMiscPEMGenerator( csr );
	    	
	        pw.writeObject( gen );
		} catch (IOException e) {

			e.printStackTrace();
		}
		/// C&P section, sw, pw: EOS

	    return sw.toString();
	}
	
	
	
	
	private X509Certificate genCertificate( 
				X509Certificate cert ,
				
				PrivateKey privateKey,
				PublicKey publicKey,
				
				String organizationIdentifier,
				String ncaName,
				String ncaId,			
				List<String> rolesList
			) throws CertIOException {
		
		

		Security.addProvider(new BouncyCastleProvider());
		
		
		try {
			
			
			X509CertificateHolder certholder = new JcaX509CertificateHolder(  cert  );
			
			
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
					certholder.getIssuer(),
					certholder.getSerialNumber(),
					certholder.getNotBefore(),
					certholder.getNotAfter(),
					( organizationIdentifier == null )? certholder.getSubject() : replaceOrganizationIdentifier( certholder.getSubject(), organizationIdentifier ),
				    publicKey
			);
			

		    QCStatement qcst = qcStatementForRoles( ncaName, ncaId, rolesList );
		    
		    final ASN1EncodableVector qcsts = new ASN1EncodableVector();
		    qcsts.add(qcst);
		    
		    
		    // Copy all other extensions verbatim, either replace or append qcStatements
		    List<ASN1ObjectIdentifier> list = certholder.getExtensionOIDs();

		    boolean isPresent = false;
		    for (ASN1ObjectIdentifier extoid : list) {
		        Extension ext = certholder.getExtension(extoid);
		        if( ext.getExtnId().equals( oid_QCStatements )) {
				    builder.addExtension(oid_QCStatements, false,  new DERSequence(qcsts) );
				    isPresent = true;
		        }else {
			        builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), certholder);
		        }
		    }
		    if( !isPresent) {
		    	builder.addExtension(oid_QCStatements, false,  new DERSequence(qcsts) );
			}
		    

		    //--------
		    
		    
		    		    
			
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").build( privateKey );
	
		    X509CertificateHolder newcert = builder.build(sigGen);
		
			
			return new JcaX509CertificateConverter().getCertificate(newcert);
		
		} catch (OperatorCreationException e) {
			throw new RuntimeException( e );
		
		} catch (CertificateException e) {
				throw new RuntimeException( e );
		}
		
	}

	
	
	public String addPsdAttibutes( String certificate, String privatekey, String passphrase, String organizationIdentifier, String ncaname, String ncaid, List<String> roles ) {
		
		
		
		
		String pemCertificate = certificate.replaceAll("\\\\n", "\n");

		


	    
		
		EiDASCertificate eidascert = new EiDASCertificate();

		
		
		
		KeyPair kp = eidascert.getKeyPair( privatekey, passphrase );

		X509Certificate cert = eidascert.getCertificate( pemCertificate );

		
		// ----------------------------------------------
		
		
		X509Certificate newcert=null;
		try {
			newcert = eidascert.genCertificate( cert,  kp.getPrivate(), kp.getPublic(), organizationIdentifier, ncaname, ncaid, roles );
		} catch (CertIOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		
		
//		try {
//			eidascert.setRolesOfPSP(cert, new String[]{ "PSP_AS","PSP_PI" } );
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		String certpem = eidascert.writeCertPem( newcert );
		
		return certpem;
	}	
	
	protected KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		
		// generate key pair
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize( 2048 );
		
		KeyPair keyPair = generator.generateKeyPair();
		
		return keyPair;
	}
	
	protected String privateKeyPem( KeyPair keyPair, String passphrase ) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
				
		// 
		StringWriter writer = new StringWriter();
		
		JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
		try {
			if( passphrase != null ) {
				final PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC").setProvider("BC").build( passphrase.toCharArray() );
				
				final JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator( rsaPrivateKey, encryptor );
		        
		        pemWriter.writeObject( pemGenerator);
		        
			}else {

				final PemObject pemObject = new PemObject( "RSA PRIVATE KEY", rsaPrivateKey.getEncoded());
				
				pemWriter.writeObject( pemObject );
			}
		} finally {
			pemWriter.flush();
			pemWriter.close();
		}
		
		return writer.toString();
	}
	
	private boolean isCACertificate( String constraint) {
		
		// isCA certificate
		Pattern pattern = Pattern.compile( "CA: *(.*)" );
		Matcher matcher = pattern.matcher( constraint );
		
		
		if( matcher.matches() ) {
			return Boolean.parseBoolean( matcher.group(1) );
		}else {
			return false;
		}
		
	}
	
	// TODO: refactor with XREF:createCertificateFromJson
	// XXXXXXXXXXX

	public X509Certificate createCertificateFromJson( 
			String json, 

			PrivateKey privateKey,
			PublicKey publicKey
		) throws OperatorCreationException, CertIOException, CertificateException {
		
		JsonObject certdesc = (new JsonParser()).parse( json ).getAsJsonObject();
		
		JsonObject certinfo = certdesc.getAsJsonObject("certInfo");
	
		
	 
		
		String issuerDN = certinfo.get("issuer").getAsString();
		String subjectDN = certinfo.get("subject").getAsString();
		
		long notBefore = certinfo.get("validFrom").getAsLong() / 1000L;;
		long notAfter = certinfo.get("expiryDate").getAsLong() / 1000L;;

		BigInteger serialNumber = certinfo.get("serialNumber").getAsBigInteger();
		
		
		JcaX509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(
				new X500Name( issuerDN ),
				serialNumber,
				Date.from( Instant.ofEpochSecond( notBefore ) ),
				Date.from( Instant.ofEpochSecond( notAfter ) ),
				new X500Name( replaceOverrides( subjectDN ) ),
			    publicKey
		);
		 
		boolean isCA = isCACertificate( certinfo.get("basicConstraints").getAsString() );
		certbuilder.addExtension( Extension.basicConstraints, false, new BasicConstraints( isCA ) );
		
// TODO: refactor against createCertificationRequestFromJson
		
		// Key Usage 
		JsonElement keyUsageJsonElement = certinfo.get("keyUsage");
		if( keyUsageJsonElement != null ) {
			int kus = getKeyUsagesFromJson( keyUsageJsonElement.getAsJsonArray() );
			if( kus != 0 ) {
				certbuilder.addExtension(Extension.keyUsage,true, new KeyUsage( kus) );
			}
		}

		// Extended Key Usage
		JsonElement extKeyUsageJsonElement = certinfo.get("extKeyUsage");
		if( extKeyUsageJsonElement != null ) {
			List<KeyPurposeId> keyPurposeIds =  getExtKeyUsageFromJsonArray( extKeyUsageJsonElement.getAsJsonArray() );
			certbuilder.addExtension(
						Extension.extendedKeyUsage, true,
			            new ExtendedKeyUsage( keyPurposeIds.toArray( new KeyPurposeId[0] ) )
			);
		}
		
		
		// QcStatements collector
	    final ASN1EncodableVector qcsts = new ASN1EncodableVector();

	    /// QcTypes Statement
		List<String> typesList = new ArrayList<String>();

		JsonElement types = certinfo.get("qcTypes");
		if( types != null ) {
			for( JsonElement t: types.getAsJsonArray() ) {
				typesList.add( t.getAsString() );
			}
	
			QCStatement qcTypeSt = qcStatementForQcType( typesList );
		    qcsts.add( qcTypeSt );
		}

	    
	    
		/// C&P section, psd2 attributes:
		
		// TODO: check for existance of ncaName and ncaId below and throw exceptions
		JsonElement roles = certinfo.get("rolesOfPSP");
		if( roles != null ) {
			String ncaName = certinfo.get("ncaName").getAsString();
			
			String ncaId =  certinfo.get("ncaId").getAsString();
			
			List<String> rolesList = new ArrayList<String>();

			for( JsonElement r: roles.getAsJsonArray() ) {
				rolesList.add( r.getAsString() );
			}
	
		    QCStatement qcPsd2St = qcStatementForRoles( ncaName, ncaId, rolesList );
		    
		    qcsts.add( qcPsd2St );
		}

		certbuilder.addExtension(oid_QCStatements, false,  new DERSequence(qcsts) );
		   
	    
	    
	    
	    // 
	    // AIA & CRL: for CSR sign or stand-alone cert [TODO] gen only
	    //
	    
		// Authority Information Access
		JsonElement aiaElement = certinfo.get("aia");
		if( aiaElement != null ) {
			JsonObject aia = aiaElement.getAsJsonObject();
			
			JsonElement caIssuers = aia.get( "caIssuers" );
			if( caIssuers == null ) {
				throw new RuntimeException( "EIDAS: aia object does not have defined: caIssuers." );
			}
			AccessDescription adCaIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers,
			        new GeneralName( GeneralName.uniformResourceIdentifier, 
			        	new DERIA5String( 
			        			caIssuers.getAsString() 
			        )));
			JsonElement ocsp = aia.get( "ocsp" );
			if( ocsp == null ) {
				throw new RuntimeException( "EIDAS: aia object does not have defined: ocsp." );
			}
			AccessDescription adOcsp = new AccessDescription(AccessDescription.id_ad_ocsp,
			        new GeneralName( GeneralName.uniformResourceIdentifier, 
			        		new DERIA5String(
			        				ocsp.getAsString()
			        )));
			 
			ASN1EncodableVector aiaASN1 = new ASN1EncodableVector();
			aiaASN1.add( adCaIssuers );
			aiaASN1.add( adOcsp );
			 
			certbuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence( aiaASN1 ));
		}
		
		// CRL Distribution Points
		JsonElement crlDps = certinfo.get("crlDPs");
		if( crlDps != null ) {
			List<DistributionPoint> dps = new ArrayList<DistributionPoint>();
			
			for( JsonElement dp: crlDps.getAsJsonArray() ) {
				DistributionPointName distPointOne = new DistributionPointName(new GeneralNames(
				        new GeneralName(
				        	GeneralName.uniformResourceIdentifier,
				        	dp.getAsString()
				   )));

				dps.add( new DistributionPoint(distPointOne, null, null) );
			}
	
			certbuilder.addExtension(Extension.cRLDistributionPoints, false, 
					new CRLDistPoint( dps.toArray( new DistributionPoint[0] ) )
				);
		}
		   
		// Sign and build
		ContentSigner signer =  new JcaContentSignerBuilder("SHA1withRSA").build( privateKey );;
		
	    X509CertificateHolder cert = certbuilder.build( signer );
	
		
		return new JcaX509CertificateConverter().getCertificate( cert );
	}
}
