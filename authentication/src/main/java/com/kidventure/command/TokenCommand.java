package com.kidventure.command;

import com.kidventure.enums.Authority;

import java.io.Serializable;
import java.util.List;

public class TokenCommand implements Serializable {

    private static final long serialVersionUID = 6710061358371752955L;

    private String token;
    private String userUuid;
    private List<Authority> authorities;

    public TokenCommand(String token, String userUuid) {
        this.token = token;
        this.userUuid = userUuid;
    }

    public TokenCommand(String token, String userUuid, List<Authority> authorities) {
        this.token = token;
        this.userUuid = userUuid;
        this.authorities = authorities;
    }

    public String getToken() {
        return token;
    }

    public String getUserUuid() {
        return userUuid;
    }


    public void setToken(String token) {
        this.token = token;
    }

    public void setUserUuid(String userUuid) {
        this.userUuid = userUuid;
    }

    public List<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }
}
