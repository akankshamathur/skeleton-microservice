package com.kidventure.config.security.service;

import com.kidventure.config.security.constants.SecurityConstants;
import com.kidventure.controller.ApiController;
import com.kidventure.exception.ServiceException;
import com.kidventure.model.User;
import com.kidventure.repository.UserRepository;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JsonWebTokenService implements TokenService {
    @Value("${security.token.secret.key}")
    private String tokenKey;
    final
    private UserDetailsService userDetailsService;
    final
    private BCryptPasswordEncoder passwordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(JsonWebTokenService.class);

    @Autowired
    public JsonWebTokenService(BCryptPasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public String getToken(final String username, final String password) {
        if (username == null || password == null) {
            return null;
        }
        final User user = (User) userDetailsService.loadUserByUsername(username);

        Map<String, Object> tokenData = new HashMap<>();
        if (passwordEncoder.matches(password, user.getPassword())) {
            tokenData.put("clientType", "user");
            tokenData.put("uuid", user.getUuid());
            tokenData.put("authority", user.getAuthorities());
            tokenData.put("token_create_date", new Date());
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DATE, SecurityConstants.TOKEN_EXP_IN_DAYS);
            tokenData.put("token_expiration_date", calendar.getTime());
            JwtBuilder jwtBuilder = Jwts.builder();
            jwtBuilder.setExpiration(calendar.getTime());
            jwtBuilder.setClaims(tokenData);
            return jwtBuilder.signWith(SignatureAlgorithm.HS512, tokenKey).compact();
        } else {
            throw new ServiceException("Authentication error", this.getClass().getName());
        }
    }

//    public static void setTokenExpirationTime(final int tokenExpirationTime) {
//        JsonWebTokenService.tokenExpirationTime = tokenExpirationTime;
//    }
}
