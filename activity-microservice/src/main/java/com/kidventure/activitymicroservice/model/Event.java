package com.kidventure.activitymicroservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.hateoas.config.EnableEntityLinks;

import java.util.Date;
import java.util.UUID;

@Document
public class Event {
    @Id
    private String id;
    private String uuid = UUID.randomUUID().toString();
    private String name;
    private String description;
    private Date dateFrom;
    private Date dateTo;
    private String price;
    private String comment;
    private String categoryId;
    private String userId;

    public Event() {
    }

    public Event(String id, String uuid, String name, String description, Date dateFrom, Date dateTo, String price, String comment, String categoryId, String userId) {
        this.id = id;
        this.uuid = uuid;
        this.name = name;
        this.description = description;
        this.dateFrom = dateFrom;
        this.dateTo = dateTo;
        this.price = price;
        this.comment = comment;
        this.categoryId = categoryId;
        this.userId = userId;
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

    public Date getDateFrom() {
        return dateFrom;
    }

    public void setDateFrom(Date dateFrom) {
        this.dateFrom = dateFrom;
    }

    public Date getDateTo() {
        return dateTo;
    }

    public void setDateTo(Date dateTo) {
        this.dateTo = dateTo;
    }

    public String getPrice() {
        return price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(String categoryId) {
        this.categoryId = categoryId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
