package com.example.security.model;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import static com.example.security.constants.JwtSecurityConstants.SECRET;

public class JwtTokenGenerator {


    public String generate(JwtUser inJwtUser) {

        Claims claims = Jwts.claims()
                        .setSubject(inJwtUser.getUserName());

        claims.put("userId", String.valueOf(inJwtUser.getId()));
        claims.put("role", inJwtUser.getRole());

        return Jwts.builder().setClaims(claims)
                .signWith(SignatureAlgorithm.HS256,SECRET)
                .compact();
    }
}
