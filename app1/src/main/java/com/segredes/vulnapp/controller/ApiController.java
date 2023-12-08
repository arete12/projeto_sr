package com.segredes.vulnapp.controller;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.segredes.vulnapp.auth.JWTUtil;
import com.segredes.vulnapp.auth.UserRepository;
import com.segredes.vulnapp.model.ChangePic;
import com.segredes.vulnapp.model.LoginReq;
import com.segredes.vulnapp.model.User;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/api")
public class ApiController {

    private final AuthenticationManager authenticationManager;
    private JWTUtil jwtUtil;
    private UserRepository userRepository;

    @Autowired
    private ConfigurableApplicationContext context;

    private static Logger logger = LoggerFactory.getLogger(ApiController.class);

    public ApiController(AuthenticationManager authenticationManager, JWTUtil jwtUtil, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
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
    @RequestMapping(value = "export", method = RequestMethod.GET)
    public ResponseEntity exportdb(HttpServletResponse response) {
        logger.info("export() - Received request /api/export");

        // TODO: Security Patch - Convert to JSON format instead of serialized
        // String fileSerialized = userRepository.storeState();
        Type setType = new TypeToken<HashSet<User>>() {
        }.getType();
        Gson gson = new Gson();
        String jsonDb = gson.toJson(UserRepository.getUserDB(), setType);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=userDB.json");
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");
        headers.add(HttpHeaders.CONTENT_LENGTH, String.valueOf(jsonDb.length()));

        return new ResponseEntity<>(jsonDb, headers, HttpStatus.OK);
    }

    @ResponseBody
    @RequestMapping(value = "/import", method = RequestMethod.POST)
    public ResponseEntity importUsers(@RequestParam("file") MultipartFile file, HttpServletResponse response) {
        logger.info("importUsers() - Received request /api/import");

        try {
            if (file.isEmpty()) {
                throw new IllegalArgumentException("Import file is empty");
            }

            // TODO: Security Patch - Convert from JSON to object

            Type setType = new TypeToken<HashSet<User>>() {
            }.getType();
            Gson gson = new Gson();
            byte[] filebytes = file.getBytes();
            String fileContent = new String(filebytes, java.nio.charset.StandardCharsets.UTF_8);
            HashSet<User> importedDb = gson.fromJson(fileContent, setType);

            UserRepository.setUserDB(importedDb);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/");
            return new ResponseEntity<>(headers, HttpStatus.FOUND);

        } catch (Exception e) {
            logger.error("Error importing state", e);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", "/");
            return new ResponseEntity<>(headers, HttpStatus.BAD_REQUEST);
        }

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

            long currentTime = Instant.now().getEpochSecond();
            long timeDifference = currentTime - user.getLastPicChange();
            if (timeDifference < 60) {
                throw new Exception("Wait 1 minute before changing avatar again");
            }

            if (!changePic.isValidUrl(newImageURL)) {
                throw new Exception("Invalid URL format");
            }

            URL url = new URL(newImageURL);

            // Valida se host e IP privado
            byte[] hostAddress = InetAddress.getByName(url.getHost()).getAddress();
            if ((hostAddress[0] == 10) ||
                    (hostAddress[0] == 172 && (hostAddress[1] >= 16 && hostAddress[1] <= 31)) ||
                    (hostAddress[0] == 192 && hostAddress[1] == 168) ||
                    (hostAddress[0] == 127)) {
                throw new Exception(url + " is a private IP address.");
            }

            // Faz o request ao URL
            URLConnection connection = (URLConnection) url.openConnection();
            StringBuilder contents = new StringBuilder();

            int maxContentSize = 10 * 1024 * 1024;
            int contentLength = connection.getContentLength();

            if (contentLength < 0 || contentLength >= maxContentSize) {
                throw new Exception("Image too big. Maximum file size is 10MB");
            }

            if (!changePic.isValidImage(connection.getInputStream())) {
                throw new Exception("Image type not supported.");
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                contents.append(inputLine);
            }
            in.close();

            // TODO: Security Patch - Prevent SSRF

            // https://www.akto.io/blog/how-to-prevent-server-side-request-forgery-ssrf-as-a-developer

            /*
             * validar se url é http/https e é válido, regex, URL scheme - OK
             * validar se é IP, ou domain name e resolver, n pode ser IP privado (tipo
             * 192.168 ou 10.x.x etc) - OK
             * 
             * validar se o content type é png ou jpg - OK
             * validar o tamanho em bytes da resposta, max imagens até 1 ou 10mb por exemplo
             * - OK
             * validar magic bytes (primeiros X bytes são de ficheiro png ou jpg) - OK
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
                user.setLastPicChange(Instant.now().getEpochSecond());

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

        String githubUrl = "https://github.com/arete12/projeto_sr/releases/download/latest/vulnapp-0.0.1-SNAPSHOT.jar";
        String newPackagePath = "NEW-vulnapp-0.0.1-SNAPSHOT.jar";
        String keystorePath = "client-truststore.jks";

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

        boolean validSignature = false;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                    "jarsigner",
                    "-verify",
                    "-keystore", keystorePath,
                    "-storepass", "654321", // certificate is public
                    newPackagePath,
                    "-strict");

            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                logger.info("appupdate() - Verification successful. The JAR file is authentic!");
                validSignature = true;
            } else {
                logger.info("appupdate() - Verification FAILED.");
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        if (validSignature) {
            // Update app package
            logger.info("appupdate() - Installing the update...");

            Path sourceFilePath = Paths.get(newPackagePath);
            Path targetFilePath = Paths.get(
                    "vulnapp-0.0.1-SNAPSHOT.jar");
            Files.move(sourceFilePath, targetFilePath, StandardCopyOption.REPLACE_EXISTING);
        } else {
            logger.info("appupdate() - Update NOT installed.");
        }

        logger.info("appupdate() - Exiting application...");
        // context.close();
        System.exit(0);
    }

    private void disableSSLCertificateValidation() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            HttpsURLConnection.setDefaultHostnameVerifier(
                    (hostname, session) -> true);
            context.init(
                    null,
                    new X509TrustManager[] {
                            new X509TrustManager() {
                                @Override
                                public void checkClientTrusted(X509Certificate[] chain, String authType)
                                        throws CertificateException {
                                }

                                @Override
                                public void checkServerTrusted(X509Certificate[] chain, String authType)
                                        throws CertificateException {
                                }

                                public X509Certificate[] getAcceptedIssuers() {
                                    return new X509Certificate[0];
                                }
                            }
                    },
                    new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
