package com.segredes.vulnapp.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.tomcat.util.descriptor.web.ContextHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
import com.segredes.vulnapp.VulnappApplication;
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

    @Autowired
    private ConfigurableApplicationContext context;

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

        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = UserRepository.findUser(username);

        // Validar se o URL e de uma imagem valida, senao mostra erro
        String newImageURL = changePic.getNewUrl();

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

            // TODO: Security Patch - Prevent SSRF

            // https://www.akto.io/blog/how-to-prevent-server-side-request-forgery-ssrf-as-a-developer

            /*
             * validar se url é http/https e é válido, regex, URL scheme
             * validar se é IP, ou domain name e resolver, n pode ser IP privado (tipo
             * 192.168 ou 10.x.x etc)
             * 
             * validar se o content type é png ou jpg
             * validar o tamanho em bytes da resposta, max imagens até 1 ou 10mb por exemplo
             * validar magic bytes (primeiros X bytes são de ficheiro png ou jpg)
             * criar um temporizador para dar delay ao utilizador, evitar que mude imagem
             * 1000 vezes em 3 segundos = 1000 requests
             * 
             * fazer conversão ou re-encoding da imagem usando alguma lib, tipo mudar
             * tamanho img para 100x100 px
             * 
             * 
             */

            String contentType = connection.getHeaderField("Content-Type");

            if (contentType != null && (contentType.startsWith("image/png")
                    || contentType.startsWith("image/jpeg")
                    || contentType.startsWith("image/jpg"))) {

                user.setPicUrl(changePic.getNewUrl());

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

    @ResponseBody
    @RequestMapping(value = "/appupdate", method = RequestMethod.POST)
    public void appupdate(HttpServletRequest request, HttpServletResponse response) throws IOException {

        logger.info("appupdate() - Request to /api/appupdate");

        String githubUrl = "https://url-do-site-de-updates/";
        String newPackagePath = "NEW-vulnapp-0.0.1-SNAPSHOT.jar";

        disableSSLCertificateValidation(); // Ignore SSL/TLS errors, self-signed certs

        URL url = new URL(githubUrl);
        URLConnection connection = (URLConnection) url.openConnection();

        try (InputStream inputStream = connection.getInputStream();
                FileOutputStream outputStream = new FileOutputStream(newPackagePath)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            logger.info("appupdate() - File downloaded!");

        }

        // TODO: Security patch - Updates: Verify if new .jar is signed before updating

        // Update app package
        Path sourceFilePath = Paths.get(newPackagePath);
        Path targetFilePath = Paths.get("vulnapp-0.0.1-SNAPSHOT.jar");
        Files.move(sourceFilePath, targetFilePath, StandardCopyOption.REPLACE_EXISTING);

        logger.info("appupdate() - Exiting application...");
        // context.close();
        System.exit(0);
    }

    private static void disableSSLCertificateValidation() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            } };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
