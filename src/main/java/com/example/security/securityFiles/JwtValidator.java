package com.example.security.securityFiles;

import com.example.security.model.JwtUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import static com.example.security.constants.JwtSecurityConstants.SECRET;

@Component
public class JwtValidator {
    public JwtUser validate(String token) {

        JwtUser jwtUser = null;

        try {
            Claims claims = Jwts.parser()
                                .setSigningKey(SECRET)
                                .parseClaimsJws(token)
                                .getBody();

            jwtUser = new JwtUser();

            jwtUser.setUserName(claims.getSubject());
            jwtUser.setId(Long.parseLong((String) claims.get("userId")));
            jwtUser.setRole((String) claims.get("role"));

        }
        catch (Exception e) {
            System.out.println(e);
        }


        return jwtUser;
    }
}
