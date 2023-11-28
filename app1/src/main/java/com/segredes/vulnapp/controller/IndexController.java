package com.segredes.vulnapp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.segredes.vulnapp.auth.UserRepository;
import com.segredes.vulnapp.config.MvcConfig;
import com.segredes.vulnapp.model.LoginReq;
import com.segredes.vulnapp.model.User;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class IndexController {

    private static Logger logger = LoggerFactory.getLogger(IndexController.class);

    @RequestMapping(value = "/" /* , method = RequestMethod.GET */)
    public String index(Model model) {
        logger.info("index() - Received request to '/' (index)");

        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        // User user = UserRepository.findUser(userDetails.getUsername());

        logger.info("index() - Security context, username: {}", username);

        String profilePicURL = UserRepository.findUser(username).getPicUrl();
        profilePicURL = (profilePicURL == null) ? "/default-user.jpeg" : profilePicURL;

        model.addAttribute("profilePicURL", profilePicURL);

        return "index";
    }
}
