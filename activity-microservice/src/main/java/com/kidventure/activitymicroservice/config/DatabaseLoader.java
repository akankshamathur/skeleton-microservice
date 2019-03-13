package com.kidventure.activitymicroservice.config;

import com.kidventure.activitymicroservice.model.Category;
import com.kidventure.activitymicroservice.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DatabaseLoader implements CommandLineRunner {
    @Autowired
    CategoryRepository categoryRepository;

    @Override
    public void run(String... args) throws Exception {
        createCategory();
    }

    private void createCategory() {
        if (categoryRepository.findByName("ABC") == null) {
            Category category = new Category("ABC", "ABCD ABCD", "9-10", Boolean.TRUE);
            categoryRepository.save(category);
        }
    }
}
