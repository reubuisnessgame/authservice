package com.github.reubuisnessgame.gamebank.authservice.form;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthForm {
    private String username;
    private String password;

    @JsonCreator
    public AuthForm(@JsonProperty("username") String username,@JsonProperty("password") String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
