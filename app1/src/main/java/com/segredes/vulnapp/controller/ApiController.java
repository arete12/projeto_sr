package com.segredes.vulnapp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.segredes.vulnapp.model.LoginReq;
import com.segredes.vulnapp.model.ChangePic;
import com.segredes.vulnapp.model.LoginRes;
import com.segredes.vulnapp.model.User;

import com.segredes.vulnapp.auth.JWTUtil;
import com.segredes.vulnapp.auth.UserRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/api")
public class ApiController {

    private final AuthenticationManager authenticationManager;
    private JWTUtil jwtUtil;

    private static Logger logger = LoggerFactory.getLogger(ApiController.class);

    public ApiController(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

    }

    @ResponseBody
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity login(LoginReq loginReq, HttpServletResponse response) {

        logger.info("login() - Received request /api/login");

        try {
            Authentication authentication = authenticationManager
                    .authenticate(
                            new UsernamePasswordAuthenticationToken(loginReq.getUsername(), loginReq.getPassword()));

            User user = UserRepository.findUser(authentication.getName());
            if (user == null) {
                throw new BadCredentialsException(null);
            }

            String token = jwtUtil.createToken(user);

            // Define o access token como um cookie para manter a sessao "stateful"
            Cookie cookie = new Cookie("access_token", token);
            cookie.setMaxAge(JWTUtil.accessTokenValidity);
            cookie.setHttpOnly(true);
            cookie.setPath("/");

            // Adiciona cookie a resposta e redireciona para /
            response.addCookie(cookie);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        } catch (BadCredentialsException e) {
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @ResponseBody
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity logout(HttpServletRequest request, HttpServletResponse response) {
        logger.info("logout() - Received request /api/logout");

        Cookie cookie = new Cookie("access_token", "");
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "/");

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @ResponseBody
    @RequestMapping(value = "/changepic", method = RequestMethod.POST)
    public ResponseEntity changepic(ChangePic changePic, HttpServletRequest request, HttpServletResponse response) {

        logger.info("changepic() - Received request /api/changepic");

        User user = UserRepository.findUser(changePic.getUsername());
        user.setPicUrl(changePic.getNewurl());

        String token = jwtUtil.createToken(user);

        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(JWTUtil.accessTokenValidity);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        response.addCookie(cookie);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "/");
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

}
