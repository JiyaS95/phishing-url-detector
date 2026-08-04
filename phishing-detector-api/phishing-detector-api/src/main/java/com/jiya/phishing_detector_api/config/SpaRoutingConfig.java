package com.jiya.phishing_detector_api.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SpaRoutingConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/scan-history").setViewName("forward:/index.html");
        registry.addViewController("/faq").setViewName("forward:/index.html");
        registry.addViewController("/community").setViewName("forward:/index.html");
        registry.addViewController("/feedback-form").setViewName("forward:/index.html");
        registry.addViewController("/extension").setViewName("forward:/index.html");
    }
}
