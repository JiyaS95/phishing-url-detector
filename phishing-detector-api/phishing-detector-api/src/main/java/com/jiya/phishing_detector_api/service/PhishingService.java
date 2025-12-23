package com.jiya.phishing_detector_api.service;

import com.jiya.phishing_detector_api.detector.URLChecker;
import com.jiya.phishing_detector_api.detector.URLResult;


import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.HashSet;


@Service
public class PhishingService {
    private Set<String> whitelist = new HashSet<>();
    private Set<String> blacklist = new HashSet<>();

    public PhishingService() {
        whitelist.add("google.com");
        whitelist.add("github.com");


        blacklist.add("phishing.com");
        blacklist.add("badsite.com");

    }

    public URLResult analyze (String url) {
        return URLChecker.analyze(url, whitelist, blacklist);
    }
}
