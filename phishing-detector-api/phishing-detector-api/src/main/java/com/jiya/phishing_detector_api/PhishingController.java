package com.jiya.phishing_detector_api;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController // class answers web requests
public class PhishingController {
    @GetMapping("/check") //when someone goes to /hello
    public Map <String, Object> checkURL(@RequestParam String url) { //we want to return this function
    ///check?url=http://example.com --> grab the url from the web address and put it in the url variable
        
        return Map.of("url", "example.com",
                        "risk", "LOW", 
                        "score", 10); //send this back to the browser
    }
}