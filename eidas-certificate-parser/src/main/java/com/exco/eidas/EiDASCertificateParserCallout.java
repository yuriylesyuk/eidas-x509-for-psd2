package com.exco.eidas;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.jce.provider.JCEECPublicKey;

import com.apigee.flow.execution.Action;
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.common.hash.Hashing;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class EiDASCertificateParserCallout implements Execution {

	private static final ASN1ObjectIdentifier etsiPsd2Roles = new ASN1ObjectIdentifier("0.4.0.19495.2");

	private Map<String, String> properties;

	public EiDASCertificateParserCallout(Map<String, String> properties) {

		this.properties = properties;
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

	private String getRolesOfPSP(X509Certificate cert) throws Exception {

		List<String> rolesList = new ArrayList<String>();

		byte[] extv = cert.getExtensionValue(Extension.qCStatements.getId());
		ASN1OctetString akiOc = ASN1OctetString.getInstance(extv);

		ASN1Sequence qcStatements;

		// try{
		qcStatements = (ASN1Sequence) new ASN1InputStream(akiOc.getOctets()).readObject();

// Some implementations assume QCStatements instead of QCStatement in this case, we need to strip for loop 
// and load the qcStatement as per following line			
//			QCStatement qcStatement = QCStatement.getInstance(qcStatements);
		for (int i = 0; i < qcStatements.size(); i++) {
			final QCStatement qcStatement = QCStatement.getInstance(qcStatements.getObjectAt(i));

			if (!etsiPsd2Roles.getId().equals(qcStatement.getStatementId().getId())) {
				// panic if not a psd2 roles statement

				int x = 3;

			}

			ASN1Encodable statementInfo = qcStatement.getStatementInfo();

			ASN1Sequence psd2QcType = ASN1Sequence.getInstance(statementInfo);

			ASN1Sequence roles = ASN1Sequence.getInstance(psd2QcType.getObjectAt(0));
			DERUTF8String nCAName = DERUTF8String.getInstance(psd2QcType.getObjectAt(1));
			DERUTF8String nCAId = DERUTF8String.getInstance(psd2QcType.getObjectAt(2));
			//

			for (int r = 0; r < roles.size(); r++) {

				ASN1Sequence role = ASN1Sequence.getInstance(roles.getObjectAt(r));

				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(role.getObjectAt(0));
				DERUTF8String roleOfPSPName = DERUTF8String.getInstance(role.getObjectAt(1));

				rolesList.add(roleOfPSPName.getString());

			}
		}

		// }catch(){}

		return "[" + rolesList.stream().map(r -> "\"" + r + "\"").reduce((rs, r) -> rs + "," + r).get() + "]";
	}

	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
		String pemCertificate = null;

		try {
			pemCertificate = ((String)messageContext.getVariable( this.properties.get("pem-certificate") )).replaceAll("\\\\n", "\n");

			if (!(pemCertificate == null) && pemCertificate.contains("BEGIN CERTIFICATE")) {
				//

				ByteArrayInputStream inputStream = new ByteArrayInputStream(pemCertificate.getBytes());

				CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
				X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);

				Date expiryDate = cert.getNotAfter();
				Date validFromDate = cert.getNotBefore();

				Date now = new Date();

				// TODO: certificate validity

				Gson gson = new Gson();

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

				// Calculate fingerprints: sha1/sha256
				String fingerprintSha256 = Hashing.sha256().hashBytes(cert.getEncoded()).toString();
				certAttributes.addProperty("fingerprintSha256", fingerprintSha256);

				String fingerprintSha1 = Hashing.sha1().hashBytes(cert.getEncoded()).toString();
				certAttributes.addProperty("fingerprintSha1", fingerprintSha1);

				// qcExtentions
				certAttributes.addProperty("rolesOfPSP", getRolesOfPSP(cert));

				String certificateVariable = this.properties.get("certificate-info");

				messageContext.setVariable(certificateVariable, certObject.toString());

			}
			return ExecutionResult.SUCCESS;
		} catch (Exception e) {

			ExecutionResult executionResult = new ExecutionResult(false, Action.ABORT);

			executionResult.setErrorResponse(e.getMessage());
			executionResult.addErrorResponseHeader("ExceptionClass", e.getClass().getName());

			messageContext.setVariable("CERTIFICATE", pemCertificate);

			messageContext.setVariable("JAVA_ERROR", e.getMessage());
			messageContext.setVariable("JAVA_STACKTRACE", Arrays.toString(Thread.currentThread().getStackTrace()));
			return executionResult;

		}
	}

}
