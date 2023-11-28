package com.segredes.vulnapp.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.segredes.vulnapp.model.User;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Component
public class JWTAuthFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(JWTAuthFilter.class);

    private final JWTUtil JWTUtil;
    private ObjectMapper mapper;

    public JWTAuthFilter(JWTUtil JWTUtil, ObjectMapper mapper) {
        this.JWTUtil = JWTUtil;
        this.mapper = mapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Map<String, Object> errorDetails = new HashMap<>();

        logger.info("doFilterInternal()");

        try {
            // Obtem access token do HTTP request (cookie neste caso)
            String accessToken = JWTUtil.resolveToken(request);
            if (accessToken == null) {
                logger.info("doFilterInternal() - Null access token");

                filterChain.doFilter(request, response);
                return;
            }

            // Parse e validacao do access token
            Claims claims = JWTUtil.resolveClaims(request);
            if (claims != null & JWTUtil.validateClaims(claims)) {
                logger.info("doFilterInternal() - Valid JWT and claims");

                String username = claims.getSubject();

                User user = UserRepository.findUser(username);

                Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
                if (user.getAdmin()) {
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                }

                Authentication authentication = new UsernamePasswordAuthenticationToken(username, "",
                        grantedAuthorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

            }

        } catch (Exception e) {
            logger.info("doFilterInternal() - Exception: {}", e);

            errorDetails.put("message", "Authentication Error");
            errorDetails.put("details", e.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            mapper.writeValue(response.getWriter(), errorDetails);

        }
        filterChain.doFilter(request, response);
    }
}