package com.segredes.app1.app1.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.segredes.app1.app1.db.UserRepository;
import com.segredes.app1.app1.model.User;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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

        System.out.println("JWTAuthFilter.doFilterInternal()");

        try {
            // Obtem access token do HTTP request (cookie neste caso)
            String accessToken = JWTUtil.resolveToken(request);
            if (accessToken == null) {
                filterChain.doFilter(request, response);
                System.out.println("JWTAuthFilter.doFilterInternal() - Failed resolveToken");
                return;
            }

            // Parse e validacao do access token
            Claims claims = JWTUtil.resolveClaims(request);
            if (claims != null & JWTUtil.validateClaims(claims)) {
                String username = claims.getSubject();

                User u = UserRepository.findUser(username);
                if (u == null) {
                    throw new Exception("JWTAuthFilte.doFilterInternal() -  findUser() is null");
                }

                Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
                if (u.getAdmin()) {
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                }

                Authentication authentication = new UsernamePasswordAuthenticationToken(username, "",
                        grantedAuthorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                System.out.println("JWTAuthFilter.doFilterInternal() - Successfully validated claims");
            }

        } catch (Exception e) {
            errorDetails.put("message", "Authentication Error");
            errorDetails.put("details", e.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            mapper.writeValue(response.getWriter(), errorDetails);

            System.out.println("JWTAuthFilter.doFilterInternal() - Exception");

        }
        filterChain.doFilter(request, response);
    }
}