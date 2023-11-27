
package com.segredes.app1.app1.auth;

import com.segredes.app1.app1.model.User;
import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class JWTUtil {

    private final String secret_key = "password123";
    public static int accessTokenValidity = 60 * 60;

    private final JwtParser jwtParser;

    // private final String TOKEN_HEADER = "Authorization";
    // private final String TOKEN_PREFIX = "Bearer ";

    public JWTUtil() {
        // this.jwtParser = Jwts.parser().setSigningKey(secret_key);
        this.jwtParser = Jwts.parser();
    }

    public String createToken(User user) {

        System.out.println("JWTUtil.createToken()");

        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("isAdmin", user.getAdmin());

        Date tokenCreateTime = new Date();
        Date tokenValidity = new Date(tokenCreateTime.getTime() + TimeUnit.MINUTES.toMillis(accessTokenValidity));
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(tokenValidity)
                // .signWith(SignatureAlgorithm.HS256, secret_key)
                .compact();
    }

    private Claims parseJwtClaims(String token) {
        System.out.println("JWTUtil.parseJwtClaims()");
        return jwtParser.parseClaimsJwt(token).getBody();
        // return jwtParser.parseClaimsJws(token).getBody();
    }

    public Claims resolveClaims(HttpServletRequest req) {
        System.out.println("JWTUtil.resolveClaims()");

        try {
            String token = resolveToken(req);
            System.out.println("JWTUtil.resolveClaims() - resolveToken(): is null? " + token == null);
            return parseJwtClaims(token);
        } catch (ExpiredJwtException ex) {
            req.setAttribute("expired", ex.getMessage());
            System.out.println("JWTUtil.resolveClaims() - ExpiredJwtException");

            throw ex;
        } catch (Exception ex) {
            req.setAttribute("invalid", ex.getMessage());
            System.out.println("JWTUtil.resolveClaims() - Exception");

            throw ex;
        }
    }

    public String resolveToken(HttpServletRequest request) {
        System.out.println("JWTUtil.resolveToken()");

        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (c.getName().equals("access_token") && c.getValue().length() > 0) {
                    System.out.println("JWTUtil.resolveToken() - Found access token in cookies");

                    System.out.println(c.getName() + " " + c.getValue());
                    return c.getValue();

                }
            }
        }

        System.out.println("JWTUtil.resolveToken() - No access token in cookies");

        // resolver cookie em vez de header "Authorization"

        // String bearerToken = request.getHeader(TOKEN_HEADER);
        // if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
        // return bearerToken.substring(TOKEN_PREFIX.length());
        // }
        return null;
    }

    public boolean validateClaims(Claims claims) throws AuthenticationException {
        System.out.println("JWTUtil.validateClaims() - No access token in cookies");

        try {
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            throw e;
        }
    }

    // private List<String> getRoles(Claims claims) {
    // return (List<String>) claims.get("roles");
    // }

}