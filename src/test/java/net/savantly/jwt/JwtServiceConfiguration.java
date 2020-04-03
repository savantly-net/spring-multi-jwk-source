package net.savantly.jwt;

import java.io.IOException;
import java.text.ParseException;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import com.nimbusds.jose.JOSEException;

import net.savantly.jwt.JwtService;

@Configuration
@ConfigurationProperties("net.savantly.jwt")
public class JwtServiceConfiguration {
	
	private String secret;
	private Resource privateKeyResource;
	

	@Bean
	JwtService jwtService() throws IOException, JOSEException, ParseException {
		return new JwtService(privateKeyResource);
	}
	
	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public Resource getPrivateKeyResource() {
		return privateKeyResource;
	}

	public void setPrivateKeyResource(Resource privateKeyResource) {
		this.privateKeyResource = privateKeyResource;
	}

}