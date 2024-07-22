package com.sigei.ms_jwt_security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/demo")
    public ResponseEntity<String> demo() {
        return ResponseEntity.ok("Hello from secured url");
    }

    @GetMapping("/admin-only")
    public ResponseEntity<String> adminonly() {
        return ResponseEntity.ok("Hello from admin-only");
    }
}
