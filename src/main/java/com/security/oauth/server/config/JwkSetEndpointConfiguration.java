package com.security.oauth.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerSecurityConfiguration;

@Configuration
public class JwkSetEndpointConfiguration extends AuthorizationServerSecurityConfiguration {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .requestMatchers()
                .antMatchers("/oauth/.well-known/jwks.json")
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/.well-known/jwks.json").permitAll();
    }
}
