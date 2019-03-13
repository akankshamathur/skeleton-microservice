package com.kidventure.config;

import com.kidventure.controller.ApiController;
import com.kidventure.model.ConsumerProfile;
import com.kidventure.repository.ConsumerProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;


@Component
public class DatabaseLoader implements CommandLineRunner {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    ConsumerProfileRepository consumerProfileRepository;
    @Autowired
    AdminRepository adminRepository;
    @Autowired
    ServiceProviderRepository serviceProviderRepository;

    private static final Logger logger = LoggerFactory.getLogger(ApiController.class);

    @Override
    public void run(String... strings) throws Exception {
        createConsumer();
    }

    private void createConsumer() {
        if (consumerProfileRepository.findByUsername("consumer@gmail.com") == null) {
            ConsumerProfile consumerProfile = new ConsumerProfile();
            consumerProfile.setUsername("consumer@gmail.com");
            consumerProfile.setPassword(bCryptPasswordEncoder.encode("password"));
            consumerProfile.setFirstName("consumer");
            consumerProfile.setLastName("gmail");
            consumerProfile.setTelephoneNum("9877655433");
            consumerProfileRepository.save(consumerProfile);
        }
    }
}