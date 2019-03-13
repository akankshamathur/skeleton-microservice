package com.kidventure.config.security.service;

import com.kidventure.config.security.UserAuthentication;
import com.kidventure.exception.UserNotFoundException;
import com.kidventure.repository.UserRepository;
import io.jsonwebtoken.SignatureException;
import com.kidventure.model.User;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import com.kidventure.config.security.constants.*;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;

@Service
public class JsonWebTokenAuthenticationService implements TokenAuthenticationService {
    @Value("${security.token.secret.key}")
    private String secretKey;

    @Autowired
    UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(JsonWebTokenAuthenticationService.class);

    @Override
    public Authentication authenticate(final HttpServletRequest request) {
        final String token = request.getHeader(SecurityConstants.AUTH_HEADER_NAME);
        final String userUuid = request.getHeader(SecurityConstants.UUID);
        final Jws<Claims> tokenData = parseToken(token);
        if (tokenData != null) {
            String tokenUuid = tokenData.getBody().get("uuid").toString();
            if ((tokenUuid.equals(userUuid)) && (System.currentTimeMillis() < (Long) tokenData.getBody().get("token_expiration_date"))) {
                UserAuthentication userAuthentication = new UserAuthentication();
                userAuthentication.setAuthenticated(true);
                return userAuthentication;
            }
        }
        return null;
    }

    private Jws<Claims> parseToken(final String token) {
        if (token != null) {
            try {
                return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }
}
