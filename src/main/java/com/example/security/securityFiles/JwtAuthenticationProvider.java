package com.example.security.securityFiles;

import com.example.security.model.JwtAuthenticationToken;
import com.example.security.model.JwtUser;
import com.example.security.model.JwtUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    JwtValidator jwtValidator;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    /**
     *
     * @param username
     * @param authentication this is the token which we will receive. We have our own implementation of the class hence
     *                       we will convert this token into that type.
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String token = jwtAuthenticationToken.getToken();
        JwtUser jwtUser = jwtValidator.validate(token);
        if (jwtUser == null) {
            throw new RuntimeException("JWT token is incorrect");
        }
        //here we should get the authorities from the user object (here JwtUser)
        //for now, we are harcoding this
        List<GrantedAuthority> list = AuthorityUtils.commaSeparatedStringToAuthorityList("USER,ADMIN");
        return new JwtUserDetails(jwtUser.getUserName(), jwtUser.getId(), token, list);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
