package com.exco.eidas;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;


@Command(name="show",description = "show contents of the certificate")
 class Show  implements Callable<Void>{
    @Option(names = "--cert", required = true, description = "certificate file")
    String certFile;

    @Override
    public Void call() throws IOException {
    	
    	

		// ----------------------------------------------
		EiDASCertificate eidascert = new EiDASCertificate();

		
		String certPem = new String(Files.readAllBytes(Paths.get( certFile )));

		X509Certificate cert = eidascert.getCertificate( certPem );

		
		System.out.println( eidascert.showPem( cert ) );
		
      
      return null;
    }
}

@Command(name="set", description = "set psd2 attributes of the iedas certificate")
 class Set  implements Callable<Void>{
    @Option(names = "--cert", required = true, description = "certificate file in pem format")
    String certFile;

    @Option(names = "--key", required = true, description = "private key file in pem format")
    String keyFile;

    @Option(names = "--organizationidentifier", required = false, description = "organization identifier as per 5.2.1")
    String orgId;

    @Option(names = "--ncaname", required = false, description = "name of the competent authority")
    String ncaName;

    @Option(names = "--ncaid", required = false, description = "competent authority abbreviated unique identifier")
    String ncaId;

    @Option(names = "--roles", required = true, split = ",", description = "eidas psd roles separated by ,: PSP_AS,PSP_PI,PSP_AI,PSP_IC")
    List<String> roles;
    
    String psdAttrs;
        

    @Option(names = "--passphrase", required = false, description = "passphrase as an argument")
    String passphrase;

    @Option(names = "--passphrase:prompt", required = false, description = "ask passphrase inteactively", interactive = true)
    String passphrasePrompt;

    @Option(names = "--passphrase:env", required = false, description = "env variable that contains passphrase")
    String passphraseEnv;
   
    
    @Override
    public Void call() throws IOException {

    	// password precedence
		if( passphrase != null ) {
			  
		} else if ( passphraseEnv != null) {
			passphrase = System.getenv( passphraseEnv );
		} else if ( passphrasePrompt != null) {
			passphrase = passphrasePrompt;
		}

      
		EiDASCertificate eidascert = new EiDASCertificate();

		String cert = new String(Files.readAllBytes(Paths.get( certFile )));
	 
		String key = new String(Files.readAllBytes(Paths.get( keyFile )));
		 
		String certpem = eidascert.addPsdAttibutes( cert, key, passphrase, orgId, ncaName, ncaId, roles );

      System.out.println(certpem);
      
      return null;
    }
}
	
@Command(description = "Utility to show contents of a certificate with eiDAS/PSD2 attributes (including roles) and ability to set them.",
	name = "java -jar ospr.jar", mixinStandardHelpOptions = true, 
	version = "iedaspsd 1.0",
	subcommands = {
			HelpCommand.class,
		    Show.class,
		    Set.class}
)
public class EiDASCertificateCLI implements Callable<Void>{
	

    
    
    public static void main(String[] args) throws Exception {


  	CommandLine commandLine = new CommandLine(new EiDASCertificateCLI());
    	
  	
  	
    	commandLine.parseWithHandler(new CommandLine.RunLast(), args);
    }
    
    @Override
    public Void call() {
      	CommandLine.usage(this, System.err);
		return null;
    }
}
