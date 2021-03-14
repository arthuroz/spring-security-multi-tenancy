package com.example.springsecuritymultitenancy;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static com.example.springsecuritymultitenancy.MultipleIdps.OAuth2IdpConfig;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;

@Component
class JwtAuthenticationManagerIssuerResolver
        implements AuthenticationManagerResolver<HttpServletRequest> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(JwtAuthenticationManagerIssuerResolver.class);

    public static final String NO_PREFIX_FOR_AUTHORITIES = "";

    private final MultipleIdps config;
    private final BearerTokenResolver resolver = new DefaultBearerTokenResolver();
    private final JwtClaimIssuerConverter issuerConverter = new JwtClaimIssuerConverter();
    private ConcurrentHashMap<String, AuthenticationManager> authenticationManagers =
            new ConcurrentHashMap<>();

    @Autowired
    public JwtAuthenticationManagerIssuerResolver(MultipleIdps config) {
        this.config = config;
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest context) {
        var issuer = issuerConverter.convert(context);
        if (config.isTrustedIssuer(issuer)) {
            return authenticationManagers.computeIfAbsent(
                    issuer,
                    (iss) -> {
                        LOGGER.info(
                                "Creating AuthenticationManager for unregistered issuer {}", iss);
                        return jwtAuthProvider(config.getIdpConfigForIssuer(iss))::authenticate;
                    });
        } else {
            throw new InvalidBearerTokenException(String.format("Untrusted issuer %s", issuer));
        }
    }

    private DefaultJWTProcessor configureJwksCache(OAuth2IdpConfig config) {
        try {
            var jwkSetCache =
                    new DefaultJWKSetCache(
                            config.jwkCacheTtl.toMinutes(),
                            config.jwkCacheRefresh.toMinutes(),
                            TimeUnit.MINUTES);
            var jwsKeySelector =
                    JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(
                            new RemoteJWKSet<>(new URL(config.jwkSetUri), null, jwkSetCache));

            var jwtProcessor = new DefaultJWTProcessor();
            jwtProcessor.setJWSKeySelector(jwsKeySelector);
            return jwtProcessor;
        } catch (KeySourceException | MalformedURLException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    private DelegatingOAuth2TokenValidator validators(OAuth2IdpConfig config) {
        var audienceValidator =
                new JwtClaimValidator<List<String>>(
                        AUD, aud -> config.audiences.stream().anyMatch(a -> aud.contains(a)));
        var validateAudienceAndIssuer =
                new DelegatingOAuth2TokenValidator(
                        JwtValidators.createDefaultWithIssuer(config.issuerUri), audienceValidator);
        return validateAudienceAndIssuer;
    }

    private JwtAuthenticationProvider jwtAuthProvider(OAuth2IdpConfig config) {
        var jwtDecoder = new NimbusJwtDecoder(configureJwksCache(config));
        jwtDecoder.setJwtValidator(validators(config));
        var authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(customJwtAuthenticationConverter());
        return authenticationProvider;
    }

    private JwtAuthenticationConverter customJwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
                new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(NO_PREFIX_FOR_AUTHORITIES);
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Override
    public String toString() {
        return "JwtAuthenticationManagerIssuerResolver{" + "config=" + config + '}';
    }

    private class JwtClaimIssuerConverter implements Converter<HttpServletRequest, String> {
        @Override
        public String convert(@NonNull HttpServletRequest request) {
            try {
                return Optional.ofNullable(
                                JWTParser.parse(resolver.resolve(request))
                                        .getJWTClaimsSet()
                                        .getStringClaim(ISS))
                        .orElseThrow(() -> new InvalidBearerTokenException("Missing issuer"));
            } catch (Exception ex) {
                throw new InvalidBearerTokenException(ex.getMessage(), ex);
            }
        }
    }
}
