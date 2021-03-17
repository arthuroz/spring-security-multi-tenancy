package com.example.springsecuritymultitenancy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import net.bytebuddy.utility.RandomString;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationManagerIssuerResolverTest {
    static MockWebServer server;

    @Mock MockHttpServletRequest request;

    @BeforeAll
    public static void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
    }

    @AfterAll
    public static void tearDown() throws IOException {
        server.shutdown();
    }

    @Nested
    class Resolver {
        @Test
        void resolveAndCacheTrustedIdp() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder = new TokenBuilder(config.user);
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            when(request.getHeader(AUTHORIZATION)).thenReturn(bearTokenString(jwt));

            var authManager = resolver.resolve(request);
            var authManager2 = resolver.resolve(request);

            assertSame(authManager, authManager2);
        }

        @Test
        void supportTwoIdps() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/idp1").toString(), server.url("/idp2").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilderForIdp1 = new TokenBuilder(config.user);
            var tokenIdp1 = bearTokenString(tokenBuilderForIdp1.build());

            var tokenBuilderForIdp2 = new TokenBuilder(config.admin);
            var tokenIdp2 = bearTokenString(tokenBuilderForIdp2.build());

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilderForIdp1.getJwks()));

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilderForIdp2.getJwks()));

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenIdp1).thenReturn(tokenIdp2);

            var authManagerIdp1 = resolver.resolve(request);
            var authManagerIdp2 = resolver.resolve(request);

            assertNotSame(authManagerIdp1, authManagerIdp2);
        }

        @Test
        void rejectUntrustedIdp() throws Exception {
            var resolver =
                    new JwtAuthenticationManagerIssuerResolver(
                            CannedData.multipleIdps(
                                    server.url("/trusted1").toString(),
                                    server.url("/trusted2").toString()));

            MultipleIdps.OAuth2IdpConfig untrustedIdp =
                    new MultipleIdps.OAuth2IdpConfig(
                            "https://arthur-dev.au.auth0.com/admin",
                            server.url("/untrusted").toString(),
                            Duration.ofMinutes(30),
                            Duration.ofMinutes(10),
                            server.url("/untrusted/.well-known/jwks.json").toString());
            var tokenFromUntrustedIdp = bearTokenString(new TokenBuilder(untrustedIdp).build());

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenFromUntrustedIdp);

            assertThrows(InvalidBearerTokenException.class, () -> resolver.resolve(request));
        }
    }

    @Nested
    class AuthenticationManager {
        @Test
        void validToken() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder = new TokenBuilder(config.user);
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            var tokenString = bearTokenString(jwt);

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenString);

            var authManager = resolver.resolve(request);
            org.springframework.security.core.Authentication authenticate =
                    authManager.authenticate(
                            new BearerTokenAuthenticationToken(buildAccessToken(jwt)));
            assertTrue(authenticate.isAuthenticated());
            assertEquals(
                    tokenBuilder.scopes,
                    authenticate.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()));
        }

        @Test
        void expiredToken() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder =
                    new TokenBuilder(config.user).withExp(Instant.now().minusSeconds(1000));
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            var tokenString = bearTokenString(jwt);

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenString);

            var authManager = resolver.resolve(request);
            assertThrows(
                    InvalidBearerTokenException.class,
                    () ->
                            authManager.authenticate(
                                    new BearerTokenAuthenticationToken(buildAccessToken(jwt))));
        }

        @Test
        void futureToken() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder =
                    new TokenBuilder(config.user).withIat(Instant.now().plusSeconds(1000));
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            var tokenString = bearTokenString(jwt);

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenString);

            var authManager = resolver.resolve(request);
            assertThrows(
                    InvalidBearerTokenException.class,
                    () ->
                            authManager.authenticate(
                                    new BearerTokenAuthenticationToken(buildAccessToken(jwt))));
        }

        @Test
        void wrongAudience() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder =
                    new TokenBuilder(config.user).withAudiences(List.of(RandomString.make()));
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            var tokenString = bearTokenString(jwt);

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenString);

            var authManager = resolver.resolve(request);
            assertThrows(
                    InvalidBearerTokenException.class,
                    () ->
                            authManager.authenticate(
                                    new BearerTokenAuthenticationToken(buildAccessToken(jwt))));
        }

        @Test
        void wrongIssuer() throws Exception {
            var config =
                    CannedData.multipleIdps(
                            server.url("/").toString(), server.url("/notcalled").toString());
            var resolver = new JwtAuthenticationManagerIssuerResolver(config);

            var tokenBuilder = new TokenBuilder(config.user).withIssuer(config.admin.issuerUri);
            var jwt = tokenBuilder.build();

            server.enqueue(
                    new MockResponse()
                            .setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                            .setBody(tokenBuilder.getJwks()));

            var tokenString = bearTokenString(jwt);

            when(request.getHeader(AUTHORIZATION)).thenReturn(tokenString);

            var authManager = resolver.resolve(request);
            assertThrows(
                    InvalidBearerTokenException.class,
                    () ->
                            authManager.authenticate(
                                    new BearerTokenAuthenticationToken(buildAccessToken(jwt))));
        }
    }

    private String bearTokenString(SignedJWT jwt) {
        return String.format("bearer %s", buildAccessToken(jwt));
    }

    private String buildAccessToken(SignedJWT jwt) {
        return String.join(
                ".", List.of(new String(jwt.getSigningInput()), jwt.getSignature().toString()));
    }

    static class TokenBuilder implements Cloneable {
        KeyPair keyPair;
        Date iat = Date.from(Instant.now().minusSeconds(60));
        Date exp = Date.from(Instant.now().plusSeconds(300));
        List<String> scopes = List.of("read:greetings", "write:greetings");
        String kid = UUID.randomUUID().toString();
        String issuer;
        List audiences;

        TokenBuilder(MultipleIdps.OAuth2IdpConfig config) throws Exception {
            this.issuer = config.issuerUri;
            this.audiences = config.audiences;
            var keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.genKeyPair();
        }

        SignedJWT build() throws Exception {
            var jwtClaimsSet =
                    new JWTClaimsSet.Builder()
                            .issuer(issuer)
                            .subject(UUID.randomUUID().toString())
                            .audience(String.join(",", audiences))
                            .expirationTime(exp)
                            .issueTime(iat)
                            .claim("scope", String.join(" ", scopes))
                            .build();

            var header =
                    new JWSHeader.Builder(JWSAlgorithm.PS256)
                            .type(JOSEObjectType.JWT)
                            .keyID(kid)
                            .build();
            var signedJWT = new SignedJWT(header, jwtClaimsSet);
            signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));

            return signedJWT;
        }

        TokenBuilder withIat(Instant iat) throws CloneNotSupportedException {
            var builder = (TokenBuilder) this.clone();
            builder.iat = Date.from(iat);
            return builder;
        }

        TokenBuilder withExp(Instant exp) throws CloneNotSupportedException {
            var builder = (TokenBuilder) this.clone();
            builder.exp = Date.from(exp);
            return builder;
        }

        TokenBuilder withIssuer(String issuer) throws CloneNotSupportedException {
            var builder = (TokenBuilder) this.clone();
            builder.issuer = issuer;
            return builder;
        }

        TokenBuilder withAudiences(List audiences) throws CloneNotSupportedException {
            var builder = (TokenBuilder) this.clone();
            builder.audiences = audiences;
            return builder;
        }

        String getJwks() {
            return new JWKSet(
                            List.of(
                                    new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                                            .algorithm(JWSAlgorithm.PS256)
                                            .keyUse(KeyUse.SIGNATURE)
                                            .keyID(kid)
                                            .build()))
                    .toJSONObject()
                    .toJSONString();
        }
    }
}
