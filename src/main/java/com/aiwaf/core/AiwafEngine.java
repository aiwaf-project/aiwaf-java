package com.aiwaf.core;

import com.aiwaf.runtime.BlacklistManager;
import com.aiwaf.runtime.RuntimeStorage;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class AiwafEngine {
    private final AiwafConfig config;
    private final Map<String, Deque<Long>> requestBuckets = new HashMap<>();
    private final Map<String, Long> lastGetPerIpPath = new HashMap<>();
    private final Map<String, Deque<RecentRequest>> recentRequestsByIp = new HashMap<>();
    private final LazyModelProviderCore modelProvider;
    private final AiwafTelemetryCore telemetry = new AiwafTelemetryCore();
    private final Set<String> defaultMaliciousKeywords = new HashSet<>(Set.of(
            ".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell", "filemanager"
    ));

    public AiwafEngine(AiwafConfig config) {
        this.config = config;
        this.modelProvider = new LazyModelProviderCore(config.aiModelPath);
        RuntimeStorage.initialize(config.storageBackend, config.storageFilePath);
        if (config.aiEnabled) {
            if (!config.aiLazyLoadModel) {
                modelProvider.get();
            } else if (config.aiBackgroundPreload) {
                Thread t = new Thread(modelProvider::get, "aiwaf-model-preload");
                t.setDaemon(true);
                t.start();
            }
        }
    }

    public synchronized void clearState() {
        requestBuckets.clear();
        lastGetPerIpPath.clear();
        recentRequestsByIp.clear();
        telemetry.reset();
    }

    public AiwafConfig config() {
        return config;
    }

    public AiwafTelemetryCore telemetry() {
        return telemetry;
    }

    public synchronized AiwafDecision evaluate(AiwafRequest req) {
        long startedNs = System.nanoTime();
        telemetryIncrement("requests.total");
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
            AiwafDecision d = AiwafDecision.deny(403, "IP blacklisted");
            return finalizeDecision(d, startedNs, "ip_blacklisted");
        }

        if (config.methodValidationEnabled && !config.isMethodAllowed(req.method())) {
            AiwafDecision d = AiwafDecision.deny(405, "Method not allowed");
            return finalizeDecision(d, startedNs, "method_validation");
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "ip_keyword_block")
                && config.ipKeywordBlockEnabled) {
            String matchedKeyword = detectMaliciousKeyword(req.path());
            if (matchedKeyword != null) {
                telemetryIncrement("middleware.ip_keyword_block.triggered");
                RuntimeStorage.getKeywordStore().addKeyword(matchedKeyword, 1);
                blockWithContext(ip, req, "Keyword block: " + matchedKeyword);
                AiwafDecision d = AiwafDecision.deny(403, "Malicious keyword: " + matchedKeyword);
                return finalizeDecision(d, startedNs, "ip_keyword_block");
            }
            String learned = detectLearnedKeyword(req.path());
            if (learned != null) {
                telemetryIncrement("middleware.ip_keyword_block.learned_triggered");
                blockWithContext(ip, req, "Learned keyword block: " + learned);
                AiwafDecision d = AiwafDecision.deny(403, "Learned keyword: " + learned);
                return finalizeDecision(d, startedNs, "ip_keyword_learned_block");
            }
            maybeLearnKeywords(req);
        }

        if (!isRuleDisabled(req, rule, config, "uuid_tamper") && config.uuidTamperEnabled) {
            String uuidValue = req.query().get("uuid");
            if (uuidValue != null && !isValidUuid(uuidValue)) {
                telemetryIncrement("middleware.uuid_tamper.triggered");
                AiwafDecision d = AiwafDecision.deny(403, "Invalid UUID");
                return finalizeDecision(d, startedNs, "uuid_tamper");
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
                        telemetryIncrement("middleware.honeypot.page_expired");
                        AiwafDecision d = AiwafDecision.deny(409, "page_expired");
                        return finalizeDecision(d, startedNs, "honeypot_page_expired");
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
                        telemetryIncrement("middleware.honeypot.timing_violation");
                        AiwafDecision d = AiwafDecision.deny(403, "Honeypot timing violation");
                        return finalizeDecision(d, startedNs, "honeypot_timing");
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
                telemetryIncrement("middleware.header_validation.triggered");
                AiwafDecision d = AiwafDecision.deny(403, headerIssue);
                return finalizeDecision(d, startedNs, "header_validation");
            }
        }

        if (!pathExempted && !isRuleDisabled(req, rule, config, "geo_block") && config.geoBlockEnabled && !ipExempted) {
            String country = safeUpper(req.country());
            if (!config.geoAllowedCountries.isEmpty() && !config.geoAllowedCountries.contains(country)) {
                telemetryIncrement("middleware.geo_block.allowlist_denied");
                AiwafDecision d = AiwafDecision.deny(403, "Geo allow list denied");
                return finalizeDecision(d, startedNs, "geo_allowlist");
            }
            boolean blockedByConfig = config.geoBlockedCountries.contains(country);
            boolean blockedByStore = RuntimeStorage.getGeoBlockStore().getCountries().contains(country);
            if (blockedByConfig || blockedByStore) {
                telemetryIncrement("middleware.geo_block.blocked");
                AiwafDecision d = AiwafDecision.deny(403, "Geo blocked");
                return finalizeDecision(d, startedNs, "geo_block");
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
                if (config.blockIpOnFloodBreach) blockWithContext(ip, req, "Flood pattern");
                telemetryIncrement("middleware.rate_limit.flood");
                AiwafDecision d = AiwafDecision.deny(403, "Flood pattern");
                return finalizeDecision(d, startedNs, "rate_limit_flood");
            }
            if (bucket.size() >= maxRequests) {
                if (config.blockIpOnRateLimitBreach) blockWithContext(ip, req, "Rate limit exceeded");
                telemetryIncrement("middleware.rate_limit.exceeded");
                AiwafDecision d = AiwafDecision.deny(429, "Rate limit exceeded");
                return finalizeDecision(d, startedNs, "rate_limit");
            }
            bucket.addLast(req.nowEpochMillis());
        }

        if (!pathExempted && !ipExempted && config.aiEnabled) {
            AiwafDecision aiDecision = evaluateAiAnomaly(req, ip);
            if (aiDecision != null) {
                recordRecent(ip, req, aiDecision.statusCode());
                return finalizeDecision(aiDecision, startedNs, "ai_anomaly");
            }
        }

        AiwafDecision allow = AiwafDecision.allow();
        recordRecent(ip, req, allow.statusCode());
        return finalizeDecision(allow, startedNs, "allow");
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

    private AiwafDecision evaluateAiAnomaly(AiwafRequest req, String ip) {
        TrainedModelCore trainedModel = modelProvider.get();
        if (trainedModel == null || trainedModel.payload() == null) {
            return null;
        }
        Object ifObj = trainedModel.payload().get("isolation_forest");
        if (!(ifObj instanceof Map<?, ?> ifMap)) {
            return null;
        }
        Object modelObj = ifMap.get("model");
        if (!(modelObj instanceof IsolationForestCore.Model model)) {
            return null;
        }
        Object namesObj = ifMap.get("feature_names");
        if (!(namesObj instanceof List<?> rawNames) || rawNames.isEmpty()) {
            return null;
        }

        String matched = detectMaliciousKeyword(req.path());
        int kwHits = matched == null ? 0 : 1;
        int burst = recentBurst(ip, req.nowEpochMillis());
        int total404 = recent404(ip, req.nowEpochMillis(), config.aiRecentWindowSeconds);
        int pathDepth = 0;
        if (req.path() != null) {
            for (String p : req.path().split("/")) {
                if (!p.isBlank()) pathDepth++;
            }
        }

        double[] row = new double[rawNames.size()];
        for (int i = 0; i < rawNames.size(); i++) {
            String name = String.valueOf(rawNames.get(i));
            row[i] = switch (name) {
                case "path_len" -> req.path() == null ? 0.0 : req.path().length();
                case "kw_hits" -> kwHits;
                case "status_code" -> 200.0;
                case "status_idx" -> 0.0;
                case "response_time_ms" -> 0.0;
                case "burst_count" -> burst;
                case "total_404" -> total404;
                case "path_depth" -> pathDepth;
                case "method_is_post" -> "POST".equalsIgnoreCase(req.method()) ? 1.0 : 0.0;
                default -> 0.0;
            };
        }

        double score = IsolationForestCore.score(model, row);
        double modelThreshold = ifMap.get("threshold") instanceof Number n ? n.doubleValue() : config.aiAnomalyScoreThreshold;
        double threshold = Math.min(modelThreshold, config.aiAnomalyScoreThreshold);
        if (score < threshold) {
            return null;
        }

        if (config.aiRequireBehaviorConfirmation) {
            int recent = recentCount(ip, req.nowEpochMillis(), config.aiRecentWindowSeconds);
            if (recent < config.aiMinRecentSamplesToBlock) {
                return null;
            }
        }

        blockWithContext(ip, req, String.format(Locale.ROOT, "AI anomaly score %.4f >= %.4f", score, threshold));
        return AiwafDecision.deny(403, String.format(Locale.ROOT, "AI anomaly score %.4f", score));
    }

    private void maybeLearnKeywords(AiwafRequest req) {
        if (!config.enableKeywordLearning || req.path() == null) {
            return;
        }
        String lower = req.path().toLowerCase(Locale.ROOT);
        if (!isMaliciousContext(lower, req.query())) {
            return;
        }
        String[] segments = lower.split("\\W+");
        int added = 0;
        for (String seg : segments) {
            if (seg == null || seg.length() <= 3) continue;
            if (config.exemptKeywords.contains(seg)) continue;
            if (config.legitimatePathKeywords.contains(seg)) continue;
            if (defaultMaliciousKeywords.contains(seg)) continue;
            RuntimeStorage.getKeywordStore().addKeyword(seg, 1);
            added++;
            if (added >= config.dynamicTopN) {
                break;
            }
        }
    }

    private boolean isMaliciousContext(String lowerPath, Map<String, String> query) {
        if (lowerPath.contains("../") || lowerPath.contains("..\\") || lowerPath.contains("%2e%2e")) {
            return true;
        }
        if (lowerPath.contains(".php") || lowerPath.contains(".env") || lowerPath.contains("wp-admin") || lowerPath.contains("phpmyadmin")) {
            return true;
        }
        if (query == null || query.isEmpty()) {
            return false;
        }
        String q = query.toString().toLowerCase(Locale.ROOT);
        return q.contains("cmd=") || q.contains("exec=") || q.contains("system=") || q.contains("union") || q.contains("<script");
    }

    private void blockWithContext(String ip, AiwafRequest req, String reason) {
        Map<String, Object> ext = config.storeExtendedBlockInfo ? extendedBlockInfo(req) : null;
        BlacklistManager.block(ip, reason, null, ext);
        telemetryIncrement("blocks.total");
    }

    private Map<String, Object> extendedBlockInfo(AiwafRequest req) {
        Map<String, Object> out = new HashMap<>();
        out.put("method", blankToDefault(req.method(), ""));
        out.put("path", blankToDefault(req.path(), ""));
        if (req.query() != null && !req.query().isEmpty()) {
            out.put("query", new HashMap<>(req.query()));
        }
        out.put("headers", redactHeaders(req.headers()));
        return out;
    }

    private Map<String, String> redactHeaders(Map<String, String> headers) {
        Map<String, String> out = new HashMap<>();
        if (headers == null || headers.isEmpty()) return out;
        int max = Math.max(1, config.blockInfoMaxHeaders);
        int maxLen = Math.max(16, config.blockInfoMaxHeaderValueLength);
        Set<String> redact = new HashSet<>();
        for (String h : config.blockInfoRedactHeaders) {
            if (h != null) redact.add(h.toLowerCase(Locale.ROOT));
        }
        int count = 0;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (count >= max) break;
            String key = e.getKey() == null ? "" : e.getKey();
            String lower = key.toLowerCase(Locale.ROOT);
            String value = e.getValue() == null ? "" : e.getValue();
            if (redact.contains(lower)) {
                out.put(key, "[redacted]");
            } else {
                if (value.length() > maxLen) {
                    value = value.substring(0, maxLen) + "...(truncated)";
                }
                out.put(key, value);
            }
            count++;
        }
        return out;
    }

    private AiwafDecision finalizeDecision(AiwafDecision decision, long startedNs, String outcomeTag) {
        long elapsedMs = (System.nanoTime() - startedNs) / 1_000_000L;
        telemetryObserve("requests.evaluate.latency_ms", elapsedMs);
        if (decision.allowed()) {
            telemetryIncrement("requests.allowed");
        } else {
            telemetryIncrement("requests.blocked");
            telemetryIncrement("requests.blocked.status." + decision.statusCode());
            telemetryIncrement("requests.blocked.outcome." + outcomeTag);
        }
        return decision;
    }

    private void telemetryIncrement(String key) {
        if (!config.observabilityEnabled) return;
        telemetry.increment(key);
    }

    private void telemetryObserve(String key, long valueMs) {
        if (!config.observabilityEnabled) return;
        telemetry.observeMs(key, valueMs);
    }

    private void recordRecent(String ip, AiwafRequest req, int statusCode) {
        Deque<RecentRequest> queue = recentRequestsByIp.computeIfAbsent(ip, k -> new ArrayDeque<>());
        queue.addLast(new RecentRequest(req.nowEpochMillis(), req.path(), statusCode));
        long cutoff = req.nowEpochMillis() - (config.aiRecentWindowSeconds * 1000L);
        while (!queue.isEmpty() && queue.peekFirst().timestampMillis() < cutoff) {
            queue.pollFirst();
        }
    }

    private int recentCount(String ip, long nowMillis, int windowSeconds) {
        Deque<RecentRequest> queue = recentRequestsByIp.get(ip);
        if (queue == null || queue.isEmpty()) return 0;
        long cutoff = nowMillis - (windowSeconds * 1000L);
        int count = 0;
        for (RecentRequest r : queue) {
            if (r.timestampMillis() >= cutoff) count++;
        }
        return count;
    }

    private int recent404(String ip, long nowMillis, int windowSeconds) {
        Deque<RecentRequest> queue = recentRequestsByIp.get(ip);
        if (queue == null || queue.isEmpty()) return 0;
        long cutoff = nowMillis - (windowSeconds * 1000L);
        int count = 0;
        for (RecentRequest r : queue) {
            if (r.timestampMillis() >= cutoff && r.statusCode() == 404) count++;
        }
        return count;
    }

    private int recentBurst(String ip, long nowMillis) {
        Deque<RecentRequest> queue = recentRequestsByIp.get(ip);
        if (queue == null || queue.isEmpty()) return 0;
        long cutoff = nowMillis - 10_000L;
        int count = 0;
        for (RecentRequest r : queue) {
            if (r.timestampMillis() >= cutoff) count++;
        }
        return count;
    }

    private record RecentRequest(long timestampMillis, String path, int statusCode) {}
}
