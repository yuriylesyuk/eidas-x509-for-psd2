package com.exco.eidas;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.apigee.flow.execution.Action;
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

public class EiDASCertificateParserCallout implements Execution {

	private static final ASN1ObjectIdentifier etsiPsd2Roles = new ASN1ObjectIdentifier("0.4.0.19495.2");

	private Map<String, String> properties;

	public EiDASCertificateParserCallout(Map<String, String> properties) {

		this.properties = properties;
	}


	public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {

		String operation = null;
		String pemCertificate = null;
		 
		EiDASCertificate eidascert = new EiDASCertificate();

		try {
			 operation = ((String)this.properties.get("operation") );
			 if( operation == null ) {
				 throw new RuntimeException( "EIDAS: operation is not set. Supported operations: sign|show");
			 }
			 
					 
			 if( operation.equals("sign") ){
				 // 'sign'
				String csrPem = ((String)messageContext.getVariable( this.properties.get("request-pem") )).replaceAll("\\\\n", "\n");
				
				PublicKey publicKey =  eidascert.getPublicKeyFromCSRPem( csrPem );

				String certificateInfo = ((String)messageContext.getVariable( this.properties.get("certificate-info") )).replaceAll("\\\\n", "\n");
					
				String keyPem = ((String)messageContext.getVariable( this.properties.get("privatekey-pem") )).replaceAll("\\\\n", "\n");
				KeyPair keyPair = eidascert.getKeyPair( keyPem, ((String)messageContext.getVariable( this.properties.get("privatekey-pem") )) );


				X509Certificate cert = eidascert.createCertificateFromJson( certificateInfo, keyPair.getPrivate(), publicKey );
					
					
				String certificateVariable = this.properties.get("certificate-pem");
				messageContext.setVariable(certificateVariable, eidascert.writeCertPem( cert ) );
					
	
			 }else if( operation.equals("show") ){
				
				X509Certificate cert = null;
				
				
				pemCertificate = ((String)messageContext.getVariable( this.properties.get("certificate-pem") )).replaceAll("\\\\n", "\n");
				
				if (!(pemCertificate == null) && pemCertificate.contains("BEGIN CERTIFICATE")) {
					cert = eidascert.getCertificate( pemCertificate );
				}
				
				
				String certificateVariable = this.properties.get("certificate-info");
				
				messageContext.setVariable(certificateVariable, eidascert.showPemAsJSON( cert ) );
				
			 
			 }else {
				 throw new RuntimeException( 
					String.format( "EIDAS: Not supported operation: %s. Supported operations: sign|show", operation)
				 );
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
