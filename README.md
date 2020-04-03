# Spring Multi JWK sources  

Currently only Webflux is support.  
Gladly accepting PRs!


## Quick start  

gradle  

```
compile 'net.savantly.security:spring-multi-jwk-source:0.0.1.RELEASE'
```

Maven  

```
<dependency>
  <groupId>net.savantly.security</groupId>
  <artifactId>spring-multi-jwk-source</artifactId>
  <version>0.0.1.RELEASE</version>
</dependency>
```


### Example Usage

```java
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
```