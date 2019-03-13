package com.kidventure.repository;

import com.kidventure.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin
public interface UserRepository extends MongoRepository<User, String> {
    User findByUsername(String username);

    User findByUuid(String uuid);
}
