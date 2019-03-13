package com.kidventure.utility.database;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@Configuration
@EnableMongoRepositories(repositoryBaseClass = InheritanceAwareSimpleMongoRepository.class,
        repositoryFactoryBeanClass = InheritanceAwareMongoRepositoryFactoryBean.class,
        basePackages = {"com.kidventure.repository"})
public class MongoConfigurer {
}
