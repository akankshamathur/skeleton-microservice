package com.kidventure.model;

import com.kidventure.enums.Authority;
import org.hibernate.validator.constraints.Length;
import org.springframework.data.annotation.Transient;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Document(collection = "users")
public abstract class User implements UserDetails {
    private static final long serialVersionUID = 7954325925563724664L;

    private String uuid = UUID.randomUUID().toString();

    @Indexed(unique = true)
    @Email(message = "*Please provide a valid Email")
    @NotEmpty(message = "*Please provide an email")
    private String username;

    private String firstName;
    private String lastName;

    @Length(min = 5, message = "*Your password must have at least 5 characters")
    @NotEmpty(message = "*Please provide your password")
    private String password;
    @Transient
    private String confirmPassword;

    public Boolean active;
    public List<Authority> authorities;
    public Boolean accountNonExpired=true;
    public Boolean accountNonLocked=true;
    public Boolean credentialsNonExpired=true;
    public Boolean isEnabled=true;

    public User() {
    }

    public User(String uuid, @Email(message = "*Please provide a valid Email") @NotEmpty(message = "*Please provide an email") String username, String firstName, String lastName, @Length(min = 5, message = "*Your password must have at least 5 characters") @NotEmpty(message = "*Please provide your password") String password, Boolean active) {
        this.uuid = uuid;
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.active = active;
    }

    public User(String username, String password, String firstName, String lastName) {
        this.username = username;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public void setAuthorities(List<Authority> authorities) {
        this.authorities = authorities;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return this.password;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    @Override
    public List<Authority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }

}
