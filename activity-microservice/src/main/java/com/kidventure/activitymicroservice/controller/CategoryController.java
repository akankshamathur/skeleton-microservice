package com.kidventure.activitymicroservice.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kidventure.activitymicroservice.model.Category;
import com.kidventure.activitymicroservice.repository.CategoryRepository;
import com.kidventure.activitymicroservice.services.impl.CategoryServiceImpl;
import com.kidventure.activitymicroservice.validator.CategoryValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping(value = "/category")
public class CategoryController {

    @Autowired
    CategoryServiceImpl categoryService;
    @Autowired
    CategoryValidator categoryValidator;
    @Autowired
    CategoryRepository categoryRepository;

    private static final Logger logger = LoggerFactory.getLogger(EventController.class);

    @InitBinder("category")
    void setupBinder(WebDataBinder binder) {
        binder.addValidators(categoryValidator);
    }

    @RequestMapping(value = "/createCategory", method = {RequestMethod.POST})
    public ResponseEntity<?> authenticate(@Valid @RequestBody final Category category) {
        if (categoryService.saveCategory(category) != null) {
            return new ResponseEntity<>("Category created", HttpStatus.OK);

        } else {
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        }
    }

    @GetMapping(value = "/allCategories", produces = "application/json;charset=UTF-8")
    String allCategories(@PageableDefault(page = 0, size = 100) Pageable pageable) throws JsonProcessingException {
        Page<Category> categories = categoryRepository.findAll(pageable);
        return new ObjectMapper().writeValueAsString(categories);
    }
}