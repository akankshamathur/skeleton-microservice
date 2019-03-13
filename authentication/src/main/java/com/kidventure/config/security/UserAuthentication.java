package com.kidventure.config.security;

import com.kidventure.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserAuthentication implements Authentication {
    private User user = null;
    private boolean authenticated = true;

    public UserAuthentication() {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.authorities;
    }

    @Override
    public Object getCredentials() {
        return user.getPassword();
    }

    @Override
    public Object getDetails() {
        return user;
    }

    @Override
    public Object getPrincipal() {
        if (user != null) {
            return user.getUsername();
        }
            return user;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(final boolean authenticated) throws IllegalArgumentException {
        this.authenticated = authenticated;
    }

    @Override
    public String getName() {
        return user.getUsername();
    }

    public User getUser() {
        return user;
    }
}
