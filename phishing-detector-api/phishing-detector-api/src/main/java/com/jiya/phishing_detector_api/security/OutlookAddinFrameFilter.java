package com.jiya.phishing_detector_api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class OutlookAddinFrameFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (request.getRequestURI().startsWith("/outlook-addin/")) {
            response.setHeader("X-Frame-Options", "");
            response.setHeader(
                "Content-Security-Policy",
                "frame-ancestors 'self' https://outlook.office.com https://outlook.office365.com https://outlook.live.com https://*.officeapps.live.com https://*.officeapps-df.live.com"
            );
        }

        filterChain.doFilter(request, response);
    }
}
