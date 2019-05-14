package com.example.security.controller;

import com.example.security.model.JwtTokenGenerator;
import com.example.security.model.JwtUser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController("/token")
public class TokenController {

    @PostMapping
    public String generateToken(@RequestBody final JwtUser inJwtUser) {

        JwtTokenGenerator jwtTokenGenerator = new JwtTokenGenerator();


        return jwtTokenGenerator.generate(inJwtUser);
    }
}
