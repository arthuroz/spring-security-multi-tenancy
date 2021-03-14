package com.example.springsecuritymultitenancy;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GreetingsController {
    @GetMapping("/")
    public String getGreetings(
            @CurrentSecurityContext(expression = "authentication.authorities[0]")
                    GrantedAuthority authority) {
        return String.format("Greetings! %s", authority.getAuthority());
    }

    @PostMapping("/")
    public String postGreetings(Authentication authentication) {
        return String.format("Hi %s!", authentication.getAuthorities());
    }
}
