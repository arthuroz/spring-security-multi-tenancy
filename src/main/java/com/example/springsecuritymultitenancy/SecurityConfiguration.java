package com.example.springsecuritymultitenancy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfiguration.class);

    private JwtAuthenticationManagerIssuerResolver resolver;

    public SecurityConfiguration(JwtAuthenticationManagerIssuerResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LOGGER.info("Configuring Spring Security resolver \n{}", resolver);
        // @formatter:off
        http
            .httpBasic().disable()
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests(authz -> authz
                .mvcMatchers(HttpMethod.GET, "/actuator/health").anonymous()
                .mvcMatchers(HttpMethod.GET, "/").hasAnyAuthority("consumer:read:greetings", "admin:read:greetings")
                .mvcMatchers(HttpMethod.POST, "/").hasAuthority("admin:write:greetings")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(resolver));
        // @formatter:on
    }
}
