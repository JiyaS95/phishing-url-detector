package com.jiya.phishing_detector_api.controller;

import java.util.Map;
import com.jiya.phishing_detector_api.detector.URLResult;
import com.jiya.phishing_detector_api.service.PhishingService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;



@RestController // class answers web requests
public class PhishingController {


    private final PhishingService phishService;

    public PhishingController (PhishingService phishService) {
        this.phishService = phishService;
    }
    @GetMapping("/check") //when someone goes to /hello
    public URLResult checkURL(@RequestParam String url) { //we want to return this function
    ///check?url=http://example.com --> grab the url from the web address and put it in the url variable
        
        return phishService.analyze(url);
    }
}

/*
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
*/