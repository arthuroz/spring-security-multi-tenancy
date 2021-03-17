package com.example.springsecuritymultitenancy;

import java.time.Duration;

public class CannedData {
    public static MultipleIdps multipleIdps(String issuer1, String issuer2) {
        return new MultipleIdps(
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/admin",
                        issuer1,
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(10),
                        issuer1 + "/.well-known/jwks.json"),
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/user",
                        issuer2,
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(10),
                        issuer2 + "/.well-known/jwks.json"));
    }
}
