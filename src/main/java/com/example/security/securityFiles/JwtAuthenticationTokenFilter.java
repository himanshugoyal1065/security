package com.example.security.securityFiles;

import com.example.security.model.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.example.security.constants.JwtSecurityConstants.HEADER;
import static com.example.security.constants.JwtSecurityConstants.INTIAL_HEADER;

/**
 * AbstractAuthenticationProcessingFilter is a superclass for UsernamePasswordAuthenticationFilter.class
 * the above class is used when we attempt to do some login activity.
 */
public class JwtAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

    public JwtAuthenticationTokenFilter() {
        super("/rest/**");
    }

    /**
     * the place where we decode the token and check for its authenticity.
     * @param request the http request
     * @param response the http response
     * @return @class : Authentication object if the user is found
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String header = request.getHeader(HEADER);
        System.out.println(header);
        if (null == header || !header.startsWith(INTIAL_HEADER)) {
            throw new RuntimeException("the jwt token is missing");
        }

        String authenticationToken = header.substring(INTIAL_HEADER.length());
        System.out.println(authenticationToken);

        JwtAuthenticationToken token = new JwtAuthenticationToken(authenticationToken);

        return getAuthenticationManager().authenticate(token);
    }

    /**
     * so that it does not block any further filters in the chain
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }
}
