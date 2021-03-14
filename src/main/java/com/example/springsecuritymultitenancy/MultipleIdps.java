package com.example.springsecuritymultitenancy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@ConstructorBinding
@ConfigurationProperties(prefix = "demo.security.oauth2.resourceserver")
class MultipleIdps {
    public final OAuth2IdpConfig admin;
    public final OAuth2IdpConfig user;
    public final Map<String, OAuth2IdpConfig> trustedIssuers;

    public MultipleIdps(OAuth2IdpConfig admin, OAuth2IdpConfig user) {
        this.admin = admin;
        this.user = user;
        trustedIssuers = Map.of(admin.issuerUri, admin, user.issuerUri, user);
    }

    @Override
    public String toString() {
        return "MultipleTenancyIdps{" + "admin=" + admin + ", user=" + user + '}';
    }

    public boolean isTrustedIssuer(String issuer) {
        return trustedIssuers.keySet().contains(issuer);
    }

    public OAuth2IdpConfig getIdpConfigForIssuer(String issuer) {
        return trustedIssuers.get(issuer);
    }

    @ConstructorBinding
    public static class OAuth2IdpConfig {
        public final List<String> audiences;
        public final String issuerUri;
        public final Duration jwkCacheTtl;
        public final Duration jwkCacheRefresh;
        public final String jwkSetUri;

        public OAuth2IdpConfig(
                String audience,
                String issuerUri,
                Duration jwkCacheTtl,
                Duration jwkCacheRefresh,
                String jwkSetUri) {
            this.audiences =
                    Arrays.stream(audience.trim().split(",\\s*"))
                            .map(String::trim)
                            .collect(Collectors.toList());
            this.issuerUri = issuerUri;
            this.jwkCacheTtl = jwkCacheTtl;
            this.jwkCacheRefresh = jwkCacheRefresh;
            this.jwkSetUri = jwkSetUri;
        }

        @Override
        public String toString() {
            return "OAuth2Config{"
                    + "audiences="
                    + audiences
                    + ", issuerUri='"
                    + issuerUri
                    + '\''
                    + ", jwkCacheTtl="
                    + jwkCacheTtl
                    + '\''
                    + ", jwkCacheRefresh="
                    + jwkCacheRefresh
                    + ", jwkSetUri='"
                    + jwkSetUri
                    + '\''
                    + '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            OAuth2IdpConfig that = (OAuth2IdpConfig) o;
            return audiences.equals(that.audiences)
                    && issuerUri.equals(that.issuerUri)
                    && jwkCacheTtl.equals(that.jwkCacheTtl)
                    && jwkCacheRefresh.equals(that.jwkCacheRefresh)
                    && jwkSetUri.equals(that.jwkSetUri);
        }

        @Override
        public int hashCode() {
            return Objects.hash(audiences, issuerUri, jwkCacheTtl, jwkCacheRefresh, jwkSetUri);
        }
    }
}
