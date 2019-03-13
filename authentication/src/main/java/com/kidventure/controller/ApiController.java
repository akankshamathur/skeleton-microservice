package com.kidventure.controller;

import com.kidventure.command.LoginCommand;
import com.kidventure.command.TokenCommand;
import com.kidventure.config.security.service.TokenService;
import com.kidventure.model.ConsumerProfile;
import com.kidventure.model.User;
import com.kidventure.repository.UserRepository;
import com.kidventure.services.impl.ConsumerProfileImpl;
import com.kidventure.utility.ApiSuccessCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/auth")
public class ApiController {

    private final TokenService tokenService;
    private final UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(ApiController.class);

    @Autowired
    ServiceProviderImpl serviceProviderService;
    @Autowired
    ConsumerProfileImpl consumerProfileService;

    @Autowired
    public ApiController(TokenService tokenService, UserRepository userRepository) {
        this.tokenService = tokenService;
        this.userRepository = userRepository;
    }

    @RequestMapping(value = "/userLogin", method = {RequestMethod.POST})
    public ResponseEntity<?> authenticate(@RequestBody final LoginCommand dto) {
        final String token = tokenService.getToken(dto.getUsername(), dto.getPassword());
        if (token != null) {
            User user = userRepository.findByUsername(dto.getUsername());
            final TokenCommand response = new TokenCommand(token, user.getUuid(), user.getAuthorities());
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            ResponseEntity responseEntity = new ResponseEntity<>("Authentication failed", HttpStatus.BAD_REQUEST);
            return responseEntity;
        }
    }

    @RequestMapping(value = "/createConsumer", method = {RequestMethod.POST})
    public ResponseEntity<?> userSignup(@RequestBody ConsumerProfile consumerProfile) {
        ApiSuccessCode response = null;
        if (consumerProfileService.save(consumerProfile) != null) {
            response = new ApiSuccessCode("200", "Successfully Created");
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        response = new ApiSuccessCode("201", "Processing Your Request");
        return new ResponseEntity<>(response, HttpStatus.ACCEPTED);
    }
}
