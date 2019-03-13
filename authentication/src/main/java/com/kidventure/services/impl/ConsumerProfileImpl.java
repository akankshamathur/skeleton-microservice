package com.kidventure.services.impl;

import com.kidventure.enums.Authority;
import com.kidventure.model.ConsumerProfile;
import com.kidventure.repository.ConsumerProfileRepository;
import com.kidventure.services.ConsumerProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service("consumerProfileService")
public class ConsumerProfileImpl implements ConsumerProfileService {
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private ConsumerProfileRepository consumerProfileRepository;

    @Override
    public ConsumerProfile save(ConsumerProfile consumerProfile) {
        consumerProfile.setPassword(bCryptPasswordEncoder.encode(consumerProfile.getPassword()));
        consumerProfile.setActive(true);
        consumerProfile.setAuthorities(Collections.singletonList(Authority.ROLE_CONSUMER));
        consumerProfile = consumerProfileRepository.save(consumerProfile);
        return consumerProfile;
    }
}
