package org.springframework.security.oauth2.jwt;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import net.minidev.json.JSONObject;
import reactor.core.publisher.Mono;

public class ReactiveMultiJwkSource implements ReactiveJWKSource {

	/**
	 * The cached JWK set.
	 */
	private final AtomicReference<Mono<JWKSet>> cachedJWKSet = new AtomicReference<>(Mono.empty());
	private ObjectMapper mapper = new ObjectMapper();

	private WebClient webClient = WebClient.create();

	private final String jwkSetURL;
	private final List<RSAKey> publicKeys = new ArrayList<>();

	ReactiveMultiJwkSource(String jwkSetURL) {
		this.jwkSetURL = jwkSetURL;
	}
	
	public void addExtraKeys(RSAKey publicKey) {
		this.publicKeys.add(publicKey);
	}

	public Mono<List<JWK>> get() {
		return getJWKSet().flatMap(jwkSet -> {
			return Mono.just(jwkSet.getKeys());
		});
	}
	
	public Mono<List<JWK>> get(JWKSelector jwkSelector) {
		return this.cachedJWKSet.get()
				.switchIfEmpty(getJWKSet())
				.flatMap(jwkSet -> get(jwkSelector, jwkSet))
				.switchIfEmpty(getJWKSet().map(jwkSet -> jwkSelector.select(jwkSet)));
	}

	private Mono<List<JWK>> get(JWKSelector jwkSelector, JWKSet jwkSet) {
		return Mono.defer(() -> {
			// Run the selector on the JWK set
			List<JWK> matches = jwkSelector.select(jwkSet);

			if (!matches.isEmpty()) {
				// Success
				return Mono.just(matches);
			}

			// Refresh the JWK set if the sought key ID is not in the cached JWK set

			// Looking for JWK with specific ID?
			String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
			if (soughtKeyID == null) {
				// No key ID specified, return no matches
				return Mono.just(Collections.emptyList());
			}

			if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
				// The key ID exists in the cached JWK set, matching
				// failed for some other reason, return no matches
				return Mono.just(Collections.emptyList());
			}

			return Mono.empty();

		});
	}

	/**
	 * Updates the cached JWK set from the configured URL.
	 *
	 * @return The updated JWK set.
	 *
	 * @throws RemoteKeySourceException If JWK retrieval failed.
	 */
	private Mono<JWKSet> getJWKSet() {
		return this.webClient.get()
				.uri(this.jwkSetURL)
				.retrieve()
				.bodyToMono(String.class)
				.map(this::addExtraKeys)
				.map(this::parse)
				.doOnNext(jwkSet -> this.cachedJWKSet.set(Mono.just(jwkSet)))
				.cache();
	}
	
	private String addExtraKeys(String jwkJson) {
		try {
			JSONObject jsonObj = mapper.readValue(jwkJson, JSONObject.class);
			Object keys = jsonObj.get("keys");
			if(Collection.class.isAssignableFrom(keys.getClass())) {
				for (RSAKey rsaKey : publicKeys) {
					JWKSet jwkSet = new JWKSet(rsaKey);
					((Collection)keys).addAll((Collection)jwkSet.toJSONObject().get("keys"));
				}
			}
			
			return jsonObj.toJSONString();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private JWKSet parse(String body) {
		try {
			return JWKSet.parse(body);
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Returns the first specified key ID (kid) for a JWK matcher.
	 *
	 * @param jwkMatcher The JWK matcher. Must not be {@code null}.
	 *
	 * @return The first key ID, {@code null} if none.
	 */
	protected static String getFirstSpecifiedKeyID(final JWKMatcher jwkMatcher) {

		Set<String> keyIDs = jwkMatcher.getKeyIDs();

		if (keyIDs == null || keyIDs.isEmpty()) {
			return null;
		}

		for (String id: keyIDs) {
			if (id != null) {
				return id;
			}
		}
		return null; // No kid in matcher
	}

}
