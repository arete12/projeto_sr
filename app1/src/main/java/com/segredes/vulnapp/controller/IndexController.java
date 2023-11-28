package com.segredes.vulnapp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.segredes.vulnapp.config.MvcConfig;
import com.segredes.vulnapp.model.LoginReq;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class IndexController {

    private static Logger logger = LoggerFactory.getLogger(IndexController.class);

    @RequestMapping(value = "/" /* , method = RequestMethod.GET */)
    public String index(HttpServletResponse request, HttpServletResponse response) {

        logger.info("index() - Received request to '/' (index)");

        return "index";
    }
}
