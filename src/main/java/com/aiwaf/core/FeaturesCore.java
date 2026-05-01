package com.aiwaf.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FeaturesCore {
    private static final Pattern TOKEN_RE = Pattern.compile("[a-zA-Z0-9_\\-]{2,64}");
    private static final Map<String, Integer> STATUS_IDX = Map.of("200", 0, "403", 1, "404", 2, "500", 3);

    private FeaturesCore() {}

    public static List<FeatureVectorCore> extractFeatures(
            List<NormalizedEvent> events,
            Set<String> staticKeywords
    ) {
        Map<String, Integer> ip404 = new HashMap<>();
        Map<String, List<Double>> ipTimes = new HashMap<>();
        for (NormalizedEvent event : events) {
            ipTimes.computeIfAbsent(event.ip(), k -> new ArrayList<>()).add((double) event.timestamp().atZone(java.time.ZoneId.systemDefault()).toEpochSecond());
            if (event.statusCode() == 404 && !event.exemptPath()) {
                ip404.put(event.ip(), ip404.getOrDefault(event.ip(), 0) + 1);
            }
        }

        List<FeatureVectorCore> vectors = new ArrayList<>();
        for (NormalizedEvent event : events) {
            double ts = event.timestamp().atZone(java.time.ZoneId.systemDefault()).toEpochSecond();
            int burst = 0;
            for (double seenTs : ipTimes.getOrDefault(event.ip(), List.of())) {
                if (Math.abs(ts - seenTs) <= 10) {
                    burst++;
                }
            }
            int kwHits = 0;
            if (!event.knownPath() && !event.exemptPath()) {
                String pathLower = event.path().toLowerCase(Locale.ROOT);
                for (String kw : staticKeywords) {
                    if (pathLower.contains(kw.toLowerCase(Locale.ROOT))) {
                        kwHits++;
                    }
                }
            }
            int pathDepth = 0;
            for (String p : event.path().split("/")) {
                if (!p.isBlank()) pathDepth++;
            }
            Map<String, Double> values = new HashMap<>();
            values.put("path_len", (double) event.path().length());
            values.put("kw_hits", (double) kwHits);
            values.put("status_code", (double) event.statusCode());
            values.put("status_idx", (double) STATUS_IDX.getOrDefault(String.valueOf(event.statusCode()), -1));
            values.put("response_time_ms", event.responseTimeMs());
            values.put("burst_count", (double) burst);
            values.put("total_404", (double) ip404.getOrDefault(event.ip(), 0));
            values.put("path_depth", (double) pathDepth);
            values.put("method_is_post", "POST".equalsIgnoreCase(event.method()) ? 1.0 : 0.0);
            vectors.add(new FeatureVectorCore(values));
        }
        return vectors;
    }

    public static List<String> extractKeywordsFromEvents(
            List<NormalizedEvent> events,
            KeywordLearningConfig config
    ) {
        Map<String, Integer> counter = new HashMap<>();
        Set<String> stopwords = new HashSet<>(config.stopwords());

        for (NormalizedEvent event : events) {
            if (event.knownPath() || event.exemptPath()) continue;
            if (event.statusCode() != 404) continue;
            if (!AnomalyCore.isScanningPath(event.path())) continue;

            Matcher matcher = TOKEN_RE.matcher(event.path().toLowerCase(Locale.ROOT));
            while (matcher.find()) {
                String token = matcher.group();
                if (token.length() < config.minTokenLength() || token.length() > config.maxTokenLength()) continue;
                if (stopwords.contains(token)) continue;
                counter.put(token, counter.getOrDefault(token, 0) + 1);
            }
        }

        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : counter.entrySet()) {
            if (entry.getValue() >= config.minOccurrenceToLearn()) {
                out.add(entry.getKey());
            }
        }
        out.sort(String::compareTo);
        return out;
    }

    public record KeywordLearningConfig(
            int minTokenLength,
            int maxTokenLength,
            int minOccurrenceToLearn,
            List<String> stopwords
    ) {
        public KeywordLearningConfig() {
            this(4, 64, 2, List.of("http", "https", "www", "api", "json", "html"));
        }
    }
}
