package org.springframework.security.oauth2.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;

import net.savantly.jwt.JwtService;

public class MultiJwtDecoderTest {

	@Test
	public void test() throws JOSEException {
		JwtService service = new JwtService("TEST");
		ReactiveMultiJwtDecoder decoder = new ReactiveMultiJwtDecoder("https://dev-931599.okta.com/oauth2/default/v1/keys", service.getRsaPublicJWK());
		List<JWK> jwks = decoder.get().block();
		assertEquals(3, jwks.size());
	}
}
