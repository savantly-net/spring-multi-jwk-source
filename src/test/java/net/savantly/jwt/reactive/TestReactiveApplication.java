package net.savantly.jwt.reactive;

import java.io.IOException;
import java.text.ParseException;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveMultiJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Controller;

import com.nimbusds.jose.JOSEException;

import net.savantly.jwt.JwtService;

@SpringBootApplication(exclude = {ReactiveOAuth2ResourceServerAutoConfiguration.class})
@Controller
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class TestReactiveApplication {

	private String oidcIssuerLocation = "https://dev-931599.okta.com/oauth2/default/v1/keys";
	private JwtService jwtService;
	
	public TestReactiveApplication() throws IOException, JOSEException, ParseException {
		// Use our custom Jwt Service to sign 
		// our Jwt service has it's own key pair, that we'll use in addition to the external OIDC
		this.jwtService = new JwtService(new ClassPathResource("test-rsa"));
	}
    
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().permitAll()
                .and()
                .csrf().disable()
                .oauth2Login().and()
            .oauth2ResourceServer()
                .jwt().jwtDecoder(jwtDecoder());
        return http.build();
    }
    
    @Bean
    public ReactiveMultiJwtDecoder jwtDecoder() {
    	// pass multiple JWK sources into the constructor
    	ReactiveMultiJwtDecoder jwtDecoder = new ReactiveMultiJwtDecoder(oidcIssuerLocation, jwtService.getRsaPublicJWK());
		return jwtDecoder;
    }
}
