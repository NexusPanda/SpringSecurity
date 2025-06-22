package com.example.SpringSecurity.JWT;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;


@Data
@NoArgsConstructor
public class LoginResponse {

    private String username;

    private String jwtToken;

    private List<String> roles;

    public LoginResponse(String username, String jwtToken, List<String> roles) {
        this.username = username;
        this.jwtToken = jwtToken;
        this.roles = roles;
    }

}
