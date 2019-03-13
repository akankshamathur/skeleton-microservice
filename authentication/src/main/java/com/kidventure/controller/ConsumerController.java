package com.kidventure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kidventure.model.User;
import com.kidventure.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/consumer")
public class ConsumerController {
    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(ConsumerController.class);

    public ConsumerController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping(value = "/fetchUser/{userUuid}", produces = "application/json;charset=UTF-8")
    public String fetchUser(@PathVariable("userUuid") String userUuid) throws JsonProcessingException {
        logger.info("inside fetch user");
        User user = userRepository.findByUuid(userUuid);
        return new ObjectMapper().writeValueAsString(user);
    }
}
