package com.kidventure.model;

import com.kidventure.enums.Authority;
import com.kidventure.enums.RelationWithChild;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;
import java.util.UUID;

@Document(collection = "users")
@TypeAlias("consumerProfile")
public class ConsumerProfile extends User {
    private String consumerUuid = UUID.randomUUID().toString();
    private String addressUuid;
    private String telephoneNum;

    public String getConsumerUuid() {
        return consumerUuid;
    }

    public void setConsumerUuid(String consumerUuid) {
        this.consumerUuid = consumerUuid;
    }

    public String getAddressUuid() {
        return addressUuid;
    }

    public void setAddressUuid(String addressUuid) {
        this.addressUuid = addressUuid;
    }

    public String getTelephoneNum() {
        return telephoneNum;
    }

    public void setTelephoneNum(String telephoneNum) {
        this.telephoneNum = telephoneNum;
    }

}
