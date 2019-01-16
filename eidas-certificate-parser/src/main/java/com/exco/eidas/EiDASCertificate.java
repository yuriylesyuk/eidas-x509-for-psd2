package com.exco.eidas;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import com.google.common.hash.Hashing;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

public class EiDASCertificate {
	
	public static final ASN1ObjectIdentifier oid_QCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");
	
    public static final ASN1ObjectIdentifier oid_etsi_psd2_qcStatement = new ASN1ObjectIdentifier( "0.4.0.19495.2" );
    
    public static final ASN1ObjectIdentifier oid_etsi_psd2_roles = new ASN1ObjectIdentifier( "0.4.0.19495.1" );
    
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_as = oid_etsi_psd2_roles.branch("1");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_pi = oid_etsi_psd2_roles.branch("2");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_ai = oid_etsi_psd2_roles.branch("3");
    public static final ASN1ObjectIdentifier oid_etsi_psd2_role_psp_ic = oid_etsi_psd2_roles.branch("4");
    
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

	
	public String showPem( X509Certificate cert ) {
		

		Date expiryDate = cert.getNotAfter();
		Date validFromDate = cert.getNotBefore();

		Date now = new Date();

		// TODO: certificate validity

		JsonObject certAttributes = new JsonObject();
		// ifnull
		// certAttributes.addProperty("keyUsage", cert.getKeyUsage());

		// getKeyUsage
		certAttributes.addProperty("basicConstraints",
				cert.getBasicConstraints() == -1 ? "CA: true" : "CA: false");

		certAttributes.addProperty("subject", cert.getSubjectDN().toString());
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
	
			// qcExtentions
			Map<String,String> attrs = getNcaAndRolesOfPSP(cert);
			

			certAttributes.addProperty("ncaName", attrs.get("ncaname"));

			certAttributes.addProperty("ncaId", attrs.get("ncaid"));

			certAttributes.addProperty("rolesOfPSP", attrs.get("roles") );


		} catch (Exception e) {

			throw new RuntimeException( e );
		}

		Gson gson =new GsonBuilder().setPrettyPrinting().create();
	
		return gson.toJson(certObject);
	}
	
	
	
	private String writePem( X509Certificate cert ) {
	
		StringWriter sw = new StringWriter();
	
		try (PemWriter pw = new PemWriter(sw)) {
			
			PemObjectGenerator gen;
			gen = new JcaMiscPEMGenerator(cert);
			pw.writeObject(gen);
		  
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

		
		}
	
		return sw.toString();
		
	
	}
	
	
	private Map<String,String> getNcaAndRolesOfPSP(X509Certificate cert) throws Exception {

		String ncaName = null;
		String ncaId = null;
		List<String> rolesList = new ArrayList<String>();

		byte[] extv = cert.getExtensionValue(Extension.qCStatements.getId());
		ASN1OctetString akiOc = ASN1OctetString.getInstance(extv);

		ASN1Sequence qcStatements;

		// try{
		qcStatements = (ASN1Sequence) new ASN1InputStream(akiOc.getOctets()).readObject();

		for (int i = 0; i < qcStatements.size(); i++) {
			final QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(i));

			if (!oid_etsi_psd2_qcStatement.getId().equals(qcStatement.getStatementId().getId())) {
				// panic if not a psd2 roles statement

				int x = 3;

			}

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

				rolesList.add(roleOfPSPName.getString());

			}
		}

		// }catch(){}
		Map<String,String> attrs = new HashMap<String,String>();
		attrs.put( "ncaname", ncaName );
		attrs.put( "ncaid", ncaId );
		attrs.put("roles", "[" + rolesList.stream().map(r -> "\"" + r + "\"").reduce((rs, r) -> rs + "," + r).get() + "]" );

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

	private KeyPair getKeyPair( String pemRSAPrivateKey, String password) {
		
		
		BufferedReader br = new BufferedReader( new InputStreamReader( new ByteArrayInputStream( pemRSAPrivateKey.getBytes() ) ) );
		
		
		try{

			 Security.addProvider(new BouncyCastleProvider());
			
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
	
	
	
	private X509Certificate genCertificate( 
				X509Certificate cert ,
				KeyPair keyPair,
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
					certholder.getSubject(),
				    keyPair.getPublic()
			);
			

		    
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

		    
		    
		    QCStatement qcst =  new QCStatement(oid_etsi_psd2_qcStatement, st);
		    
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
		    
		    
		    		    
			
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").build(keyPair.getPrivate());
	
		    X509CertificateHolder newcert = builder.build(sigGen);
		
			
			return new JcaX509CertificateConverter().getCertificate(newcert);
		
		} catch (OperatorCreationException e) {
			throw new RuntimeException( e );
		
		} catch (CertificateException e) {
				throw new RuntimeException( e );
		}
		
	}

	
	
	public String addPsdAttibutes( String certificate, String privatekey, String passphrase, String ncaname, String ncaid, List<String> roles ) {
		
		
		
		
		String pemCertificate = certificate.replaceAll("\\\\n", "\n");

		


	    
		
		EiDASCertificate eidascert = new EiDASCertificate();

		
		
		
		KeyPair kp = eidascert.getKeyPair( privatekey, passphrase );

		X509Certificate cert = eidascert.getCertificate( pemCertificate );

		
		// ----------------------------------------------
		
		
		X509Certificate newcert=null;
		try {
			newcert = eidascert.genCertificate( cert,  kp, ncaname, ncaid, roles );
		} catch (CertIOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		
		
		try {
			eidascert.setRolesOfPSP(cert, new String[]{ "PSP_AS","PSP_PI" } );
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String certpem = eidascert.writePem( newcert );
		
		return certpem;
	}	
}
