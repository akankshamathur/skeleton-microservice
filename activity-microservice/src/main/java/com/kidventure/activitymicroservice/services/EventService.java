package com.kidventure.activitymicroservice.services;

import com.kidventure.activitymicroservice.command.EventCommand;
import com.kidventure.activitymicroservice.model.Event;

public interface EventService {
    Event saveEvent(Event event);

    void deleteEvent(String uuid);

    void updateEvent(EventCommand eventCommand);
}
