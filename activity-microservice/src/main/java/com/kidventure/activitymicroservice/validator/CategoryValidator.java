package com.kidventure.activitymicroservice.validator;

import com.kidventure.activitymicroservice.model.Category;
import com.kidventure.activitymicroservice.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class CategoryValidator implements Validator {
    @Autowired
    CategoryRepository categoryRepository;

    public boolean supports(Class<?> aClass) {
        return Category.class.isAssignableFrom(aClass);
    }

    public void validate(Object o, Errors errors) {
        Category category = (Category) o;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", "NotEmpty");
        if (categoryRepository.findByName(category.getName()) != null) {
            errors.reject("ALREADY EXISTS");
        }
    }
}
