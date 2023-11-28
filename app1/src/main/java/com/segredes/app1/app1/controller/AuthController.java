package com.segredes.app1.app1.controller;

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

import com.segredes.app1.app1.model.LoginReq;
import com.segredes.app1.app1.model.ChangePic;
import com.segredes.app1.app1.model.LoginRes;
import com.segredes.app1.app1.model.User;

import ch.qos.logback.core.status.Status;

import com.segredes.app1.app1.auth.JWTUtil;
import com.segredes.app1.app1.auth.UserRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/api")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private JWTUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;

    }

    @ResponseBody
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity login(LoginReq loginReq, HttpServletResponse response) {

        System.out.println("/api/login/ - AuthController.login()");

        try {
            Authentication authentication = authenticationManager
                    .authenticate(
                            new UsernamePasswordAuthenticationToken(loginReq.getUsername(), loginReq.getPassword()));

            User user = UserRepository.findUser(authentication.getName());

            if (user == null) {
                System.out.println("/api/login/ - AuthController.login() - BadCredentials");
                throw new BadCredentialsException("");
            }

            String token = jwtUtil.createToken(user);
            System.out.println("/api/login/ - AuthController.login() - Created token");

            // Define o access token como um cookie para manter a sessao "stateful"
            Cookie cookie = new Cookie("access_token", token);
            cookie.setMaxAge(JWTUtil.accessTokenValidity);
            cookie.setHttpOnly(true);
            cookie.setPath("/");

            // Adiciona cookie a resposta e redireciona para /dashboard
            response.addCookie(cookie);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/dashboard");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        } catch (BadCredentialsException e) {
            // ErrorRes errorResponse = new ErrorRes(HttpStatus.BAD_REQUEST, "Invalid
            // username or password");
            // return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/");
            System.out.println("/api/login/ - AuthController.login() - BadCredentialsException");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        } catch (Exception e) {
            System.out.println("/api/login/ - AuthController.login() - Exception");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @ResponseBody
    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public ResponseEntity logout(HttpServletRequest request, HttpServletResponse response) {

        System.out.println("/api/logout/ - AuthController.logout()");

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

        User user = UserRepository.findUser(changePic.getUsername());
        user.setPicUrl(changePic.getNewurl());

        System.out.println("/api/changepic - AuthController.changepic()");

        String token = jwtUtil.createToken(user);
        System.out.println("/api/changepic/ - AuthController.changepic() - Created token");

        Cookie cookie = new Cookie("access_token", token);
        cookie.setMaxAge(JWTUtil.accessTokenValidity);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        response.addCookie(cookie);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "/dashboard");
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

}
