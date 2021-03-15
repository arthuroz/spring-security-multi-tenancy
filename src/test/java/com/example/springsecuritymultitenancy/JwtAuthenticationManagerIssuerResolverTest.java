package com.example.springsecuritymultitenancy;

import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationManagerIssuerResolverTest {

    @Mock MockHttpServletRequest request;

    @Mock DefaultJWTProcessor jwtProcessor;

    @Test
    void cacheTrustedIdp() {
        var resolver =
                new JwtAuthenticationManagerIssuerResolver(CannedData.validMultipleIdps()) {
                    int i = 0;

                    @Override
                    DefaultJWTProcessor configureJwksCache(MultipleIdps.OAuth2IdpConfig config) {
                        if (i == 0) {
                            assertEquals(CannedData.validMultipleIdps().user, config);
                            i++;
                        } else {
                            fail("Should reuse decoder for the same issuer");
                        }
                        return jwtProcessor;
                    }
                };

        when(request.getHeader(AUTHORIZATION)).thenReturn(CannedData.BEARER_USER);

        var authenticationManager = resolver.resolve(request);
        var cachedAuthnManager = resolver.resolve(request);

        assertTrue(authenticationManager == cachedAuthnManager);
    }

    @Test
    void supportBothIdps() {
        JwtAuthenticationManagerIssuerResolver resolver =
                new JwtAuthenticationManagerIssuerResolver(CannedData.validMultipleIdps()) {
                    int i = 0;

                    @Override
                    DefaultJWTProcessor configureJwksCache(MultipleIdps.OAuth2IdpConfig config) {
                        if (i == 0) {
                            assertEquals(CannedData.validMultipleIdps().user, config);
                            i++;
                        } else {
                            assertEquals(CannedData.validMultipleIdps().admin, config);
                        }
                        return jwtProcessor;
                    }
                };

        when(request.getHeader(AUTHORIZATION))
                .thenReturn(CannedData.BEARER_USER)
                .thenReturn(CannedData.BEARER_ADMIN);

        var user = resolver.resolve(request);
        var admin = resolver.resolve(request);

        assertTrue(user != admin);
    }

    @Test
    void rejectUntrustedIdp() {
        var resolver = new JwtAuthenticationManagerIssuerResolver(CannedData.randomMultipleIdps());

        when(request.getHeader(AUTHORIZATION)).thenReturn(CannedData.BEARER_USER);

        assertThrows(InvalidBearerTokenException.class, () -> resolver.resolve(request));
    }
}
