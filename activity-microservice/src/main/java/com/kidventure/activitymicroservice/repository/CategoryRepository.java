package com.kidventure.activitymicroservice.repository;

import com.kidventure.activitymicroservice.model.Category;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin
public interface CategoryRepository extends MongoRepository<Category,String> {
    Category findByName(String categoryName);

    Category findByUuid(String uuid);
}
