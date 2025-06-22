package com.example.SpringSecurity.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // ✅ Bypass JWT filter for H2 Console
        String path = request.getRequestURI();
        if (path.startsWith("/h2-console")) {
            filterChain.doFilter(request, response);
            return;
        }

        logger.debug("AuthTokenFilter called for URI: {}", path);
        try {
            String jwt = parseJwt(request);
            System.out.println(">>> Authorization Header: " + request.getHeader("Authorization"));
            System.out.println(">>> URI: " + path);

            if (jwt != null && jwtUtils.validateToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());
            }

        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        // ✅ Proceed with the rest of the filter chain
        filterChain.doFilter(request, response);
    }


    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java {}", jwt);
        return jwt;
    }

//    public String parseJwt(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        System.out.println("Header: " + bearerToken);
//        if (bearerToken != null) {
//            System.out.println("Starts with Bearer? " + bearerToken.startsWith("Bearer "));
//            if (bearerToken.startsWith("Bearer ")) {
//                String token = bearerToken.substring(7);
//                System.out.println("Parsed token: " + token);
//                return token;
//            }
//        }
//        return null;
//    }
}
