package com.jiya.phishing_detector_api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> windowStart = new ConcurrentHashMap<>();

    private static final int MAX_REQUESTS = 30; // per minute
    private static final long WINDOW_MS = 60_000;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        // Only rate limit API endpoints
        if (!path.startsWith("/check") && !path.startsWith("/auth") && !path.startsWith("/reports")) {
            filterChain.doFilter(request, response);
            return;
        }

        String ip = getClientIp(request);
        long now = System.currentTimeMillis();

        windowStart.putIfAbsent(ip, now);
        requestCounts.putIfAbsent(ip, new AtomicInteger(0));

        // Reset window if expired
        if (now - windowStart.get(ip) > WINDOW_MS) {
            windowStart.put(ip, now);
            requestCounts.get(ip).set(0);
        }

        int count = requestCounts.get(ip).incrementAndGet();
        if (count > MAX_REQUESTS) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Too many requests. Please wait a minute before trying again.\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
