package com.kidventure.activitymicroservice.services.impl;

import com.kidventure.activitymicroservice.model.Category;
import com.kidventure.activitymicroservice.repository.CategoryRepository;
import com.kidventure.activitymicroservice.services.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service("categoryService")
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    CategoryRepository categoryRepository;

    public Category saveCategory(Category category) {
        categoryRepository.save(category);
        return category;
    }
}
