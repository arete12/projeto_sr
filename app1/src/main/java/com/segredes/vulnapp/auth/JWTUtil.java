
package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.model.User;
import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class JWTUtil {

    private static Logger logger = LoggerFactory.getLogger(JWTUtil.class);

    private final JwtParser jwtParser;
    private final String secret_key = java.util.UUID.randomUUID().toString().replaceAll("-", "").substring(0, 32); // TODO:
                                                                                                                   // Security
                                                                                                                   // Patch
    public static int accessTokenValidity = 60 * 60;

    public JWTUtil() {
        this.jwtParser = Jwts.parser().setSigningKey(secret_key); // TODO: Security Patch
        // this.jwtParser = Jwts.parser();
    }

    public String createToken(User user) {

        logger.info("createToken() - User: {}", user.getUsername());

        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("picUrl", user.getPicUrl());

        Date tokenCreateTime = new Date();
        Date tokenValidity = new Date(tokenCreateTime.getTime() + TimeUnit.MINUTES.toMillis(accessTokenValidity));
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(tokenValidity)
                .signWith(SignatureAlgorithm.HS256, secret_key) // TODO: Security Patch
                .compact();
    }

    private Claims parseJwtClaims(String token) {
        logger.info("parseJwsClaims() - Token: {}", token);
        return jwtParser.parseClaimsJws(token).getBody(); // TODO: Security Patch
    }

    public Claims resolveClaims(HttpServletRequest req) {
        logger.info("resolveClaims()");

        try {
            String token = resolveToken(req);
            return parseJwtClaims(token);
        } catch (ExpiredJwtException ex) {
            logger.info("resolveClaims() - Expired JWT Exception: {}", ex);
            req.setAttribute("expired", ex.getMessage());
            throw ex;

        } catch (Exception ex) {
            logger.info("resolveClaims() - Exception: {}", ex);
            req.setAttribute("invalid", ex.getMessage());
            throw ex;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        logger.info("resolveToken()");

        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (c.getName().equals("access_token") && c.getValue().length() > 0) {
                    logger.info("resolveToken() - Found cookie 'access_token'");
                    return c.getValue();
                }
            }
        }

        logger.info("resolveToken() - Did not find cookie 'access_token'");
        return null;
    }

    public boolean validateClaims(Claims claims) throws AuthenticationException {

        try {
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            throw e;
        }
    }

}