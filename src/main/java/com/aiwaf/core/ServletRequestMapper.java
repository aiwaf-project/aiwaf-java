package com.aiwaf.core;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class ServletRequestMapper {
    private ServletRequestMapper() {}

    public static AiwafRequest from(HttpServletRequest req) {
        return from(req, Set.of());
    }

    public static AiwafRequest from(HttpServletRequest req, Set<String> disabledMiddlewares) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> names = req.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            headers.put(name, req.getHeader(name));
        }

        Map<String, String> query = new HashMap<>();
        req.getParameterMap().forEach((k, v) -> query.put(k, (v != null && v.length > 0) ? v[0] : ""));

        String country = getHeader(headers, "X-Country");
        String clientIp = resolveClientIp(req, headers);
        return new AiwafRequest(
                req.getMethod(),
                req.getRequestURI(),
                clientIp,
                country,
                Collections.unmodifiableMap(headers),
                Collections.unmodifiableMap(query),
                System.currentTimeMillis(),
                disabledMiddlewares == null ? Set.of() : Set.copyOf(disabledMiddlewares)
        );
    }

    private static String resolveClientIp(HttpServletRequest req, Map<String, String> headers) {
        String forwardedFor = getHeader(headers, "X-Forwarded-For");
        if (!forwardedFor.isBlank()) {
            String[] parts = forwardedFor.split(",");
            for (String part : parts) {
                String candidate = part.trim();
                if (!candidate.isBlank() && !"unknown".equalsIgnoreCase(candidate)) {
                    return candidate;
                }
            }
        }
        String realIp = getHeader(headers, "X-Real-IP");
        if (!realIp.isBlank() && !"unknown".equalsIgnoreCase(realIp)) {
            return realIp.trim();
        }
        String remote = req.getRemoteAddr();
        return (remote == null || remote.isBlank()) ? "127.0.0.1" : remote;
    }

    private static String getHeader(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue() == null ? "" : entry.getValue();
            }
        }
        return "";
    }
}
