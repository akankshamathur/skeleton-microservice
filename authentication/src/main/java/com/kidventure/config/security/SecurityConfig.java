package com.kidventure.config.security;

import com.kidventure.config.security.service.TokenAuthenticationService;
import com.kidventure.config.security.filter.AuthenticationTokenFilter;
import com.kidventure.enums.Authority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    TokenAuthenticationService tokenAuthenticationService;

    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/resources/**", "/static/**", "/css/**", "/fonts/**", "/icons/**", "/js/**", "/img/**", "/favicon.ico");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .cors().configurationSource(new CorsConfigurationSource() {

            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.addAllowedOrigin("*");
                config.setAllowCredentials(true);
                return config;
            }
        });

        http.authorizeRequests()
                .antMatchers(HttpMethod.POST, "/", "/login", "/auth/userLogin", "/userLogin", "/auth/createConsumer", "/auth/*").permitAll()
//                .antMatchers("/admin/**").hasAuthority(Authority.ROLE_ADMIN.toString())
                .antMatchers("/auth/").fullyAuthenticated()
                .and()
                .addFilterBefore(new AuthenticationTokenFilter(tokenAuthenticationService), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable();
    }
}
