package com.aiwaf.core;

import com.aiwaf.runtime.BlacklistManager;
import com.aiwaf.runtime.RuntimeStorage;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class AiwafEngine {
    private final AiwafConfig config;
    private final Map<String, Deque<Long>> requestBuckets = new HashMap<>();
    private final Map<String, Long> lastGetPerIpPath = new HashMap<>();
    private final Set<String> defaultMaliciousKeywords = new HashSet<>(Set.of(
            ".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell", "filemanager"
    ));

    public AiwafEngine(AiwafConfig config) {
        this.config = config;
        RuntimeStorage.initialize("memory", null);
    }

    public synchronized void clearState() {
        requestBuckets.clear();
        lastGetPerIpPath.clear();
    }

    public AiwafConfig config() {
        return config;
    }

    public synchronized AiwafDecision evaluate(AiwafRequest req) {
        AiwafConfig.PathRule rule = ExemptionsCore.getPathRuleForPath(req.path(), config.pathRules);
        boolean headerValidationEnabled = config.headerValidationEnabled && !isRuleDisabled(req, rule, config, "header_validation");
        int maxRequests = resolveRateLimitOverride(rule, "max", config.rateLimitMax, rule == null ? null : rule.rateLimitMaxOverride);
        int windowSeconds = resolveRateLimitOverride(rule, "window", config.rateLimitWindowSeconds, rule == null ? null : rule.rateLimitWindowOverride);
        int floodThreshold = resolveRateLimitOverride(rule, "flood", config.rateLimitFloodThreshold, rule == null ? null : rule.rateLimitFloodOverride);
        boolean pathExempted = config.isAutoExemptPath(req.path())
                || ExemptionsCore.isPathExempt(req.path(), config.exemptPaths, config.exemptAllowWildcards, config.exemptAllowPrefix)
                || RuntimeStorage.getPathExemptionStore().isExempted(req.path(), config.exemptAllowWildcards, config.exemptAllowPrefix)
                || config.geoExemptPaths.contains(req.path());
        String ip = blankToDefault(req.ip(), "127.0.0.1");
        boolean ipExempted = config.exemptIps.contains(ip) || (config.privateIpsExempted && isPrivateIp(ip));
        if (!ipExempted && BlacklistManager.isBlocked(ip)) {
            return AiwafDecision.deny(403, "IP blacklisted");
        }

        if (config.methodValidationEnabled && !config.isMethodAllowed(req.method())) {
            return AiwafDecision.deny(405, "Method not allowed");
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "ip_keyword_block")
                && config.ipKeywordBlockEnabled) {
            String matchedKeyword = detectMaliciousKeyword(req.path());
            if (matchedKeyword != null) {
                RuntimeStorage.getKeywordStore().addKeyword(matchedKeyword, 1);
                BlacklistManager.block(ip, "Keyword block: " + matchedKeyword, null);
                return AiwafDecision.deny(403, "Malicious keyword: " + matchedKeyword);
            }
            String learned = detectLearnedKeyword(req.path());
            if (learned != null) {
                BlacklistManager.block(ip, "Learned keyword block: " + learned, null);
                return AiwafDecision.deny(403, "Learned keyword: " + learned);
            }
        }

        if (!isRuleDisabled(req, rule, config, "uuid_tamper") && config.uuidTamperEnabled) {
            String uuidValue = req.query().get("uuid");
            if (uuidValue != null && !isValidUuid(uuidValue)) {
                return AiwafDecision.deny(403, "Invalid UUID");
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "honeypot") && config.honeypotEnabled) {
            String key = ip + "|" + req.path();
            if ("GET".equalsIgnoreCase(req.method())) {
                lastGetPerIpPath.put(key, req.nowEpochMillis());
            } else if ("POST".equalsIgnoreCase(req.method())) {
                Long lastGet = lastGetPerIpPath.get(key);
                if (lastGet != null) {
                    double elapsed = (req.nowEpochMillis() - lastGet) / 1000.0;
                    if (elapsed > config.maxFormPageTimeSeconds) {
                        return AiwafDecision.deny(409, "page_expired");
                    }
                    double minFormTime = config.minFormTimeSeconds;
                    String reqPathLower = req.path() == null ? "" : req.path().toLowerCase(Locale.ROOT);
                    for (String prefix : config.loginPathPrefixes) {
                        if (prefix != null && !prefix.isBlank() && reqPathLower.startsWith(prefix.toLowerCase(Locale.ROOT))) {
                            minFormTime = config.loginMinFormTimeSeconds;
                            break;
                        }
                    }
                    if (elapsed < minFormTime) {
                        return AiwafDecision.deny(403, "Honeypot timing violation");
                    }
                }
            }
        }

        if (!pathExempted && headerValidationEnabled && !ipExempted) {
            int minHeaderQualityScore = resolveOverride(rule, "header_validation", "quality_threshold", config.minHeaderQualityScore);
            int maxHeaderBytes = resolveOverride(rule, "header_validation", "max_header_bytes", config.maxHeaderBytes);
            int maxHeaderCount = resolveOverride(rule, "header_validation", "max_header_count", config.maxHeaderCount);
            int maxUserAgentLength = resolveOverride(rule, "header_validation", "max_user_agent_length", config.maxUserAgentLength);
            int maxAcceptLength = resolveOverride(rule, "header_validation", "max_accept_length", config.maxAcceptLength);
            String headerIssue = HeaderValidationCore.validate(
                    req.headers(),
                    req.method(),
                    serverProtocolFrom(req),
                    config.resolveRequiredHeaders(req.method()),
                    minHeaderQualityScore,
                    maxHeaderBytes,
                    maxHeaderCount,
                    maxUserAgentLength,
                    maxAcceptLength
            );
            if (headerIssue != null) {
                return AiwafDecision.deny(403, headerIssue);
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "geo_block") && config.geoBlockEnabled && !ipExempted) {
            String country = safeUpper(req.country());
            if (!config.geoAllowedCountries.isEmpty() && !config.geoAllowedCountries.contains(country)) {
                return AiwafDecision.deny(403, "Geo allow list denied");
            }
            boolean blockedByConfig = config.geoBlockedCountries.contains(country);
            boolean blockedByStore = RuntimeStorage.getGeoBlockStore().getCountries().contains(country);
            if (blockedByConfig || blockedByStore) {
                return AiwafDecision.deny(403, "Geo blocked");
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "rate_limit") && config.rateLimitEnabled && !ipExempted) {
            String bucketKey = config.rateLimitScope == AiwafConfig.RateLimitScope.GLOBAL_IP
                    ? ip
                    : ip + "|" + req.path();
            Deque<Long> bucket = requestBuckets.computeIfAbsent(bucketKey, k -> new ArrayDeque<>());
            long threshold = req.nowEpochMillis() - (windowSeconds * 1000L);
            while (!bucket.isEmpty() && bucket.peekFirst() < threshold) {
                bucket.pollFirst();
            }
            if (bucket.size() >= floodThreshold) {
                if (config.blockIpOnFloodBreach) BlacklistManager.block(ip, "Flood pattern", null);
                return AiwafDecision.deny(403, "Flood pattern");
            }
            if (bucket.size() >= maxRequests) {
                if (config.blockIpOnRateLimitBreach) BlacklistManager.block(ip, "Rate limit exceeded", null);
                return AiwafDecision.deny(429, "Rate limit exceeded");
            }
            bucket.addLast(req.nowEpochMillis());
        }

        return AiwafDecision.allow();
    }

    private static boolean isRuleDisabled(AiwafRequest req, AiwafConfig.PathRule rule, AiwafConfig config, String middlewareName) {
        String normalized = ExemptionsCore.normalizeMiddlewareName(middlewareName);
        if (!config.isMiddlewareEnabled(normalized)) {
            return true;
        }
        if (req.disabledMiddlewares() != null && req.disabledMiddlewares().contains(normalized)) {
            return true;
        }
        return rule != null && rule.disables(normalized);
    }

    private static String safeUpper(String s) {
        return s == null ? "" : s.toUpperCase(Locale.ROOT);
    }

    private static String serverProtocolFrom(AiwafRequest req) {
        String protocol = HeaderValidationCore.getHeader(req.headers(), ":protocol");
        if (!protocol.isBlank()) {
            return protocol;
        }
        return "HTTP/1.1";
    }

    private static boolean isValidUuid(String value) {
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private String detectMaliciousKeyword(String path) {
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);
        for (String pattern : config.blockedPathPatterns) {
            if (p.contains(pattern.toLowerCase(Locale.ROOT))) return pattern;
        }
        for (String keyword : defaultMaliciousKeywords) {
            if (p.contains(keyword.toLowerCase(Locale.ROOT))) return keyword;
        }
        return null;
    }

    private String detectLearnedKeyword(String path) {
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);
        String[] tokens = p.split("\\W+");
        Set<String> learned = new HashSet<>(RuntimeStorage.getKeywordStore().getTopKeywords(100));
        for (String token : tokens) {
            if (token.length() > 3 && learned.contains(token)) return token;
        }
        return null;
    }

    private static boolean isPrivateIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        if (ip.equals("::1")) {
            return true;
        }
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) {
            return true;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int first;
        int second;
        try {
            first = Integer.parseInt(parts[0]);
            second = Integer.parseInt(parts[1]);
        } catch (NumberFormatException ex) {
            return false;
        }
        if (first != 172) {
            return false;
        }
        return second >= 16 && second <= 31;
    }

    private static String blankToDefault(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private static int resolveOverride(AiwafConfig.PathRule rule, String middleware, String key, int fallback) {
        if (rule == null) {
            return fallback;
        }
        Integer override = rule.getOverride(middleware, key);
        return override == null ? fallback : override;
    }

    private static int resolveRateLimitOverride(AiwafConfig.PathRule rule, String key, int fallback, Integer explicitOverride) {
        if (explicitOverride != null) {
            return explicitOverride;
        }
        if (rule == null) {
            return fallback;
        }
        Integer generic = rule.getOverride("rate_limit", key);
        if (generic == null) {
            generic = rule.getOverride("RATE_LIMIT", key);
        }
        return generic == null ? fallback : generic;
    }
}
