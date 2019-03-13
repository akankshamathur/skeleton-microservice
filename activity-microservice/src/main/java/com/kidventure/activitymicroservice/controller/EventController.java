package com.kidventure.activitymicroservice.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kidventure.activitymicroservice.command.EventCommand;
import com.kidventure.activitymicroservice.model.Event;
import com.kidventure.activitymicroservice.repository.EventRepository;
import com.kidventure.activitymicroservice.services.impl.EventServiceImpl;
import com.kidventure.activitymicroservice.validator.EventValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.PagedResourcesAssembler;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping(value = "/event")
public class EventController {
    @Autowired
    EventServiceImpl eventService;
    @Autowired
    EventValidator eventValidator;
    @Autowired
    EventRepository eventRepository;
    @Autowired
    PagedResourcesAssembler<Event> pagedResourcesAssembler;
    private static final Logger logger = LoggerFactory.getLogger(EventController.class);

    @InitBinder("event")
    void setupBinder(WebDataBinder binder) {
        binder.addValidators(eventValidator);
    }

    @RequestMapping(value = "/createEvent", method = {RequestMethod.POST})
    public ResponseEntity<?> createEvent(@Valid @RequestBody final Event event) {
        if (eventService.saveEvent(event) != null) {
            return new ResponseEntity<>(OK);

        } else {
            return new ResponseEntity<>(ACCEPTED);
        }
    }

    @RequestMapping(value = "/editEvent", method = {RequestMethod.POST})
    public ResponseEntity<?> editEvent(@RequestBody final EventCommand eventCommand) {
        eventService.updateEvent(eventCommand);
        return new ResponseEntity<>(OK);
    }

    @GetMapping(value = "/allEvents", produces = "application/json;charset=UTF-8")
    String allEvents(@PageableDefault(page = 0, size = 100) Pageable pageable) throws JsonProcessingException {
        Page<Event> events = eventRepository.findAll(pageable);
        return new ObjectMapper().writeValueAsString(events);
    }

    @GetMapping(value = "eventDetail/{eventUuid}", produces = "application/json;charset=UTF-8")
    Event getEvent(@PathVariable("eventUuid") String eventUuid, @RequestHeader HttpHeaders httpHeaders) {
        Event event = eventRepository.findByUuid(eventUuid);
        return event;
    }

    @RequestMapping(value = "userEvent/{userUuid}", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
    ResponseEntity userEvents(@PathVariable("userUuid") String userUuid, Pageable pageable) throws JsonProcessingException {
        Page<Event> events = eventRepository.findAllByUserId(userUuid, pageable);
        logger.info(String.valueOf(events));
        return ResponseEntity.ok(pagedResourcesAssembler.toResource(events));
    }

    @GetMapping(value = "deleteEvent/{eventUuid}")
    String delete(@PathVariable("eventUuid") String eventUuid) {
        eventService.deleteEvent(eventUuid);
        return "Event Deleted";
    }
}
