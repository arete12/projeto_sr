
package com.segredes.app1.app1.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.segredes.app1.app1.App1Application;

@RestController
public class ExportController {

    @GetMapping("/api/export")
    public void ExportUsers() {

    }

    @PostMapping("/api/import ")
    public void ImportUsers() {

    }
}