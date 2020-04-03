package net.savantly.jwt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.core.io.Resource;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JwtService {

	private final RSAKey rsaJWK;
	private final RSAKey rsaPublicJWK;
	private final JWSSigner signer;
	
	public JwtService(String keyId) {
		
		try {
			// RSA signatures require a public and private RSA key pair, the public key 
	    	// must be made known to the JWS recipient in order to verify the signatures
	    	rsaJWK = new RSAKeyGenerator(2048)
	    	    .keyID(keyId)
	    	    .generate();
	    	rsaPublicJWK = rsaJWK.toPublicJWK();
	
	    	// Create RSA-signer with the private key
	    	signer = new RSASSASigner(rsaJWK);
		} catch (JOSEException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public JwtService(Resource privateKeyResource) throws IOException, JOSEException, ParseException {
		JWK jwk = JWK.parseFromPEMEncodedObjects(new String(readAllBytes(privateKeyResource.getInputStream())));
		String jwkString = jwk.toJSONObject().toString();
		this.rsaJWK = RSAKey.parse(jwkString);
		this.rsaPublicJWK = rsaJWK.toPublicJWK();
		this.signer = new RSASSASigner(rsaJWK);
	}

	public String createJWT(String username) {
		return createJWT(username, new ArrayList<String>());
	}
	
	public String createJWT(String username, List<String> groups) {
		return createJWT(username, groups, new ArrayList<String>());
	}
	
	public String createJWT(String username, List<String> groups, List<String> scopes) {
		return createJWT(username, groups, scopes, 60);
	}
    
    public String createJWT(String username, List<String> groups, List<String> scopes, long minToExpiration) {
    	
    	Date expirationDate = new Date(Instant.now().plus(minToExpiration, ChronoUnit.MINUTES).toEpochMilli());

    	// Prepare JWT with claims set
    	JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
    	    .subject(username)
    	    .issuer("https://savantly")
    	    .issueTime(new Date())
    	    .expirationTime(expirationDate)
    	    .claim("groups", groups)
    	    .claim("scp", scopes)
    	    .claim("preferred_username", username)
    	    .build();

    	SignedJWT signedJWT = new SignedJWT(
    	    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
    	    claimsSet);

    	// Compute the RSA signature
    	try {
			signedJWT.sign(signer);
		} catch (JOSEException e) {
			throw new RuntimeException("Failed while creating the RSA signature for the JWT");
		}

    	// To serialize to compact form, produces something like
    	// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
    	// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
    	// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
    	// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
    	String s = signedJWT.serialize();

    	// On the consumer side, parse the JWS and verify its RSA signature
    	//signedJWT = SignedJWT.parse(s);

    	return s;
    }

	public RSAKey getRsaPublicJWK() {
		return rsaPublicJWK;
	}
	
	byte[] readAllBytes(InputStream in) throws IOException {
	    ByteArrayOutputStream baos= new ByteArrayOutputStream();
	    byte[] buf = new byte[1024];
	    for (int read=0; read != -1; read = in.read(buf)) { baos.write(buf, 0, read); }
	    return baos.toByteArray();
	}

}
