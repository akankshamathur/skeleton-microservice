package com.kidventure.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Authority implements GrantedAuthority {
    ROLE_CONSUMER;

    @Override
    public String getAuthority() {
        return this.name();
    }

    Authority() {
    }
}
