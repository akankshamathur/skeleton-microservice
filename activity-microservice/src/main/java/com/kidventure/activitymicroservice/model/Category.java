package com.kidventure.activitymicroservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.UUID;

@Document
public class Category {

    @Id
    private String id;
    private String uuid = UUID.randomUUID().toString();
    private String name;
    private String description;
    private String ageGroup;
    private Boolean active = Boolean.FALSE;
    private String creatorUserId;

    public Category() {
    }

    public Category(String name, String description, String ageGroup, Boolean active) {
        this.name = name;
        this.description = description;
        this.ageGroup = ageGroup;
        this.active = active;
    }

    public Category(String id, String uuid, String name, String description, String ageGroup, Boolean active) {
        this.id = id;
        this.uuid = uuid;
        this.name = name;
        this.description = description;
        this.ageGroup = ageGroup;
        this.active = active;
    }

    public Category(String name, String description, String ageGroup, Boolean active, String creatorUserId) {
        this.name = name;
        this.description = description;
        this.ageGroup = ageGroup;
        this.active = active;
        this.creatorUserId = creatorUserId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAgeGroup() {
        return ageGroup;
    }

    public void setAgeGroup(String ageGroup) {
        this.ageGroup = ageGroup;
    }

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public String getCreatorUserId() {
        return creatorUserId;
    }

    public void setCreatorUserId(String creatorUserId) {
        this.creatorUserId = creatorUserId;
    }
}
