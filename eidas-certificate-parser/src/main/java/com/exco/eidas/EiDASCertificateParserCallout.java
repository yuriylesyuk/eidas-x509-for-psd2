package com.exco.eidas;

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

		String pemCertificate = null;

		try {

			EiDASCertificate eidascert = new EiDASCertificate();
			
			X509Certificate cert = null;
			
			
			pemCertificate = ((String)messageContext.getVariable( this.properties.get("pem-certificate") )).replaceAll("\\\\n", "\n");

			if (!(pemCertificate == null) && pemCertificate.contains("BEGIN CERTIFICATE")) {
				cert = eidascert.getCertificate( pemCertificate );
			}
			
		
			String certificateVariable = this.properties.get("certificate-info");

			messageContext.setVariable(certificateVariable, eidascert.showPemAsJSON( cert ) );

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
