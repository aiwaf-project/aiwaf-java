package com.aiwaf.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class TrainingCore {
    private TrainingCore() {}

    public static TrainedModelCore trainModel(
            List<NormalizedEvent> events,
            List<String> staticKeywords
    ) {
        if (events == null || events.isEmpty()) {
            throw new IllegalArgumentException("cannot train model from empty event list");
        }
        List<FeatureVectorCore> vectors = FeaturesCore.extractFeatures(events, new java.util.HashSet<>(staticKeywords));
        double avgResponse = 0.0;
        for (FeatureVectorCore vector : vectors) {
            avgResponse += vector.values().getOrDefault("response_time_ms", 0.0);
        }
        avgResponse /= vectors.size();

        Map<Integer, Integer> statusCounts = new HashMap<>();
        for (NormalizedEvent event : events) {
            statusCounts.put(event.statusCode(), statusCounts.getOrDefault(event.statusCode(), 0) + 1);
        }

        Map<String, Object> behavior = analyzeBehavior(events, staticKeywords, null, false);
        Map<String, Object> payload = new HashMap<>();
        payload.put("avg_response_time_ms", avgResponse);
        payload.put("status_counts", statusCounts);
        payload.put("samples", events.size());
        payload.put("behavior", behavior);
        return new TrainedModelCore("baseline-statistical", "1", payload);
    }

    public static Map<String, Object> analyzeBehavior(
            List<NormalizedEvent> events,
            List<String> staticKeywords,
            BehaviorAnalyzer rustAnalyzer,
            boolean useRustBackend
    ) {
        if (events == null || events.isEmpty()) {
            return Map.of(
                    "requests_per_ip", Map.of(),
                    "method_ratio", Map.of(),
                    "hot_paths", Map.of(),
                    "error_rate", 0.0,
                    "ip_stats", Map.of()
            );
        }

        Map<String, Integer> ipCounts = new HashMap<>();
        Map<String, Integer> methodCounts = new HashMap<>();
        Map<String, Integer> pathCounts = new HashMap<>();
        Map<String, List<NormalizedEvent>> ipEvents = new HashMap<>();
        int totalErrors = 0;

        for (NormalizedEvent e : events) {
            ipCounts.put(e.ip(), ipCounts.getOrDefault(e.ip(), 0) + 1);
            String method = e.method().toUpperCase();
            methodCounts.put(method, methodCounts.getOrDefault(method, 0) + 1);
            pathCounts.put(e.path(), pathCounts.getOrDefault(e.path(), 0) + 1);
            ipEvents.computeIfAbsent(e.ip(), k -> new ArrayList<>()).add(e);
            if (e.statusCode() >= 400) totalErrors++;
        }

        double total = events.size();
        Map<String, Double> methodRatio = new HashMap<>();
        for (Map.Entry<String, Integer> e : methodCounts.entrySet()) {
            methodRatio.put(e.getKey(), e.getValue() / total);
        }

        Map<String, Integer> requestsPerIp = new HashMap<>(ipCounts);
        Map<String, Integer> hotPaths = topN(pathCounts, 10);
        double errorRate = totalErrors / total;

        Map<String, Object> ipStats = new HashMap<>();
        for (Map.Entry<String, List<NormalizedEvent>> entry : ipEvents.entrySet()) {
            String ip = entry.getKey();
            List<NormalizedEvent> rows = entry.getValue();

            Map<String, Object> stats;
            if (useRustBackend && rustAnalyzer != null) {
                stats = rustAnalyzer.analyze(rows, staticKeywords);
            } else {
                stats = analyzeRecentBehaviorWindow(rows, staticKeywords, null, false);
            }
            ipStats.put(ip, stats);
        }

        Map<String, Object> out = new HashMap<>();
        out.put("requests_per_ip", requestsPerIp);
        out.put("method_ratio", methodRatio);
        out.put("hot_paths", hotPaths);
        out.put("error_rate", errorRate);
        out.put("ip_stats", ipStats);
        return out;
    }

    public static Map<String, Object> analyzeRecentBehaviorWindow(
            List<NormalizedEvent> events,
            List<String> staticKeywords,
            BehaviorAnalyzer rustAnalyzer,
            boolean useRustBackend
    ) {
        if (events == null || events.isEmpty()) {
            return null;
        }
        if (useRustBackend && rustAnalyzer != null) {
            return rustAnalyzer.analyze(events, staticKeywords);
        }

        List<Integer> bursts = new ArrayList<>();
        for (NormalizedEvent row : events) {
            double base = row.timestamp().atZone(java.time.ZoneId.systemDefault()).toEpochSecond();
            int burst = 0;
            for (NormalizedEvent r : events) {
                double ts = r.timestamp().atZone(java.time.ZoneId.systemDefault()).toEpochSecond();
                if (Math.abs(ts - base) <= 10) burst++;
            }
            bursts.add(burst);
        }

        int scanning404s = 0;
        int max404s = 0;
        for (NormalizedEvent row : events) {
            if (row.statusCode() == 404) {
                max404s++;
                if (AnomalyCore.isScanningPath(row.path())) scanning404s++;
            }
        }
        int legitimate404s = max404s - scanning404s;

        double avgKwHits = 0.0;
        for (NormalizedEvent row : events) {
            if (!row.knownPath() && !row.exemptPath()) {
                for (String kw : staticKeywords) {
                    if (row.path().toLowerCase().contains(kw.toLowerCase())) avgKwHits += 1;
                }
            }
        }
        avgKwHits = avgKwHits / events.size();

        double avgBurst = 0.0;
        for (Integer b : bursts) avgBurst += b;
        avgBurst = bursts.isEmpty() ? 0.0 : avgBurst / bursts.size();
        int totalRequests = events.size();

        boolean shouldBlock = evaluateBehaviorForBlocking(
                avgKwHits,
                max404s,
                avgBurst,
                totalRequests,
                scanning404s,
                legitimate404s
        );

        Map<String, Object> out = new HashMap<>();
        out.put("avg_kw_hits", avgKwHits);
        out.put("max_404s", max404s);
        out.put("avg_burst", avgBurst);
        out.put("total_requests", totalRequests);
        out.put("scanning_404s", scanning404s);
        out.put("legitimate_404s", legitimate404s);
        out.put("should_block", shouldBlock);
        return out;
    }

    public static boolean evaluateBehaviorForBlocking(
            double avgKwHits,
            int max404s,
            double avgBurst,
            int totalRequests,
            int scanning404s,
            int legitimate404s
    ) {
        if (max404s == 0 && avgKwHits == 0 && scanning404s == 0) {
            return false;
        }
        if (avgKwHits < 3
                && scanning404s < 5
                && legitimate404s < 20
                && avgBurst < 25
                && totalRequests < 150) {
            return false;
        }
        return true;
    }

    private static Map<String, Integer> topN(Map<String, Integer> counts, int n) {
        return counts.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(n)
                .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        java.util.LinkedHashMap::new
                ));
    }

    @FunctionalInterface
    public interface BehaviorAnalyzer {
        Map<String, Object> analyze(List<NormalizedEvent> events, List<String> staticKeywords);
    }
}
