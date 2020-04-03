package org.springframework.security.oauth2.jwt;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;

import reactor.core.publisher.Mono;

/**
 * An implementation of a {@link ReactiveJwtDecoder} that &quot;decodes&quot; a
 * JSON Web Token (JWT) and additionally verifies it's digital signature if the JWT is a
 * JSON Web Signature (JWS). It can be constructed with a {@link URL} and additional {@link RSAKey} instances
 *
 * <p>
 * <b>NOTES:</b> This is a modified version of {@link NimbusReactiveJwtDecoder}
 *
 * @author Rob Winch
 * @author Jeremy Branham
 * 
 * @see ReactiveJwtDecoder
 * @see <a target="_blank" href="https://github.com/spring-projects/spring-security-oauth/issues/1479#issuecomment-577366210">Issue #1479 Discussion</a>
 */
public class ReactiveMultiJwtDecoder implements ReactiveJwtDecoder {
	private final JWTProcessor<JWKContext> jwtProcessor;

	private final ReactiveMultiJwkSource reactiveJwkSource;

	private final JWKSelectorFactory jwkSelectorFactory;

	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	public ReactiveMultiJwtDecoder(String jwkSetUrl, RSAKey... key) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		String jwsAlgorithm = JwsAlgorithms.RS256;
		JWSAlgorithm algorithm = JWSAlgorithm.parse(jwsAlgorithm);
		JWKSource jwkSource = new JWKContextJWKSource();
		JWSKeySelector<JWKContext> jwsKeySelector =
				new JWSVerificationKeySelector<>(algorithm, jwkSource);

		DefaultJWTProcessor<JWKContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});
		this.jwtProcessor = jwtProcessor;

		this.reactiveJwkSource = new ReactiveMultiJwkSource(jwkSetUrl);
		for (RSAKey rsaPublicKey : key) {
			this.reactiveJwkSource.addExtraKeys(rsaPublicKey);
		}

		this.jwkSelectorFactory = new JWKSelectorFactory(algorithm);

	}
	
	public Mono<List<JWK>> get() {
		return this.reactiveJwkSource.get();
	}

	/**
	 * Use the provided {@link OAuth2TokenValidator} to validate incoming {@link Jwt}s.
	 *
	 * @param jwtValidator the {@link OAuth2TokenValidator} to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		JWT jwt = parse(token);
		if (jwt instanceof SignedJWT) {
			return this.decode((SignedJWT) jwt);
		}
		throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private Mono<Jwt> decode(SignedJWT parsedToken) {
		try {
			JWKSelector selector = this.jwkSelectorFactory
					.createSelector(parsedToken.getHeader());
			return this.reactiveJwkSource.get(selector)
				.onErrorMap(e -> new IllegalStateException("Could not obtain the keys", e))
				.map(jwkList -> createClaimsSet(parsedToken, jwkList))
				.map(set -> createJwt(parsedToken, set))
				.map(this::validateJwt)
				.onErrorMap(e -> !(e instanceof IllegalStateException) && !(e instanceof JwtException), e -> new JwtException("An error occurred while attempting to decode the Jwt: ", e));
		} catch (RuntimeException ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}
	}

	private JWTClaimsSet createClaimsSet(JWT parsedToken, List<JWK> jwkList) {
		try {
			return this.jwtProcessor.process(parsedToken, new JWKContext(jwkList));
		}
		catch (BadJOSEException | JOSEException e) {
			throw new JwtException("Failed to validate the token", e);
		}
	}

	private Jwt createJwt(JWT parsedJwt, JWTClaimsSet jwtClaimsSet) {
		Instant expiresAt = null;
		if (jwtClaimsSet.getExpirationTime() != null) {
			expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
		}
		Instant issuedAt = null;
		if (jwtClaimsSet.getIssueTime() != null) {
			issuedAt = jwtClaimsSet.getIssueTime().toInstant();
		} else if (expiresAt != null) {
			// Default to expiresAt - 1 second
			issuedAt = Instant.from(expiresAt).minusSeconds(1);
		}

		Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

		return new Jwt(parsedJwt.getParsedString(), issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());
	}

	private Jwt validateJwt(Jwt jwt) {
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);

		if ( result.hasErrors() ) {
			String message = result.getErrors().iterator().next().getDescription();
			throw new JwtValidationException(message, result.getErrors());
		}

		return jwt;
	}

	private static RSAKey rsaKey(RSAPublicKey publicKey) {
		return new RSAKey.Builder(publicKey)
				.build();
	}
}