package com.kidventure.services.impl;

import com.kidventure.model.User;
import com.kidventure.repository.UserRepository;
import com.kidventure.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service("userService")
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    public User save(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setActive(true);
        user = userRepository.save(user);
        return user;
    }
}
