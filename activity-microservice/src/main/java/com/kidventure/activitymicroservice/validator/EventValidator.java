package com.kidventure.activitymicroservice.validator;

import com.kidventure.activitymicroservice.model.Category;
import com.kidventure.activitymicroservice.model.Event;
import com.kidventure.activitymicroservice.repository.CategoryRepository;
import com.kidventure.activitymicroservice.repository.EventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class EventValidator implements Validator {
    @Autowired
    EventRepository eventRepository;

    public boolean supports(Class<?> aClass) {
        return Event.class.isAssignableFrom(aClass);
    }

    public void validate(Object o, Errors errors) {
        Event event = (Event) o;
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", "NotEmpty");
        if (eventRepository.findByName(event.getName()) != null) {
            errors.reject("ALREADY EXISTS");
        }
    }
}
