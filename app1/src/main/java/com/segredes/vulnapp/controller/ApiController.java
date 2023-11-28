package com.segredes.vulnapp.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
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
import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    public ResponseEntity changepic(ChangePic changePic, HttpServletRequest request, HttpServletResponse response)
            throws StreamWriteException, DatabindException, IOException {

        logger.info("changepic() - Received request /api/changepic");

        User user = UserRepository.findUser(changePic.getUsername());

        // Validar se o URL e de uma imagem valida, senao mostra erro
        String newImageURL = changePic.getNewurl();

        try {
            URL url = new URL(newImageURL);

            URLConnection connection = (URLConnection) url.openConnection();
            StringBuilder contents = new StringBuilder();

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                contents.append(inputLine);
            }
            in.close();

            // TODO: Security Patch

            // https://www.akto.io/blog/how-to-prevent-server-side-request-forgery-ssrf-as-a-developer

            /*
             * validar se url é http/https e é válido, regex, URL scheme
             * validar se é IP, ou domain name e resolver, n pode ser IP privado (tipo
             * 192.168 ou 10.x.x etc)
             * validar se o content type é png ou jpg
             * validar o tamanho em bytes da resposta, max imagens até 1 ou 10mb por exemplo
             * validar magic bytes (primeiros X bytes são de ficheiro png ou jpg)
             * criar um temporizador para dar delay ao utilizador, evitar que mude imagem
             * 1000 vezes em 3 segundos = 1000 requests
             * 
             */

            String contentType = connection.getHeaderField("Content-Type");

            if (contentType != null && (contentType.startsWith("image/png")
                    || contentType.startsWith("image/jpeg")
                    || contentType.startsWith("image/jpg"))) {

                user.setPicUrl(changePic.getNewurl());

                // Atualiza profile pic URL no token JWT e atualiza o cookie
                String token = jwtUtil.createToken(user);
                Cookie cookie = new Cookie("access_token", token);
                cookie.setMaxAge(JWTUtil.accessTokenValidity);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                response.addCookie(cookie);

            } else {
                throw new Exception("Invalid image: " + contents);
            }

        } catch (Exception e) {

            logger.info("changepic() - Invalid image URL {}", newImageURL);
            user.setPicUrl(null);

            Map<String, Object> errorDetails = new HashMap<>();
            ObjectMapper mapper = new ObjectMapper();

            errorDetails.put("message", "The provided URL is not a valid image");
            errorDetails.put("details", e.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            mapper.writeValue(response.getWriter(), errorDetails);

        }

        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", "/");
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

}
