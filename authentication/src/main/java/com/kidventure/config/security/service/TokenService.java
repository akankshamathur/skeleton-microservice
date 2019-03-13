package com.kidventure.config.security.service;

public interface TokenService {
    String getToken(String username, String password);
}
