package com.jiya.phishing_detector_api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;

@RestController
public class RobotsController {

    @GetMapping(value = "/robots.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> robots() {
        String robots = "User-agent: *\n" +
            "Allow: /\n" +
            "Sitemap: https://www.alurtra.linkpc.net/sitemap.xml\n";
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_PLAIN)
            .body(robots);
    }
}
