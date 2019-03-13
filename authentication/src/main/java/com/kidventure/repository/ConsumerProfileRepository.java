package com.kidventure.repository;

import com.kidventure.model.ConsumerProfile;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin
public interface ConsumerProfileRepository extends MongoRepository<ConsumerProfile, String> {
    ConsumerProfile findByConsumerUuid(String consumerUuid);

    ConsumerProfile findByUsername(String username);
}
