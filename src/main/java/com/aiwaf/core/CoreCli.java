package com.aiwaf.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class CoreCli {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Set<String> VALID_TARGETS = Set.of(
            "all",
            "features",
            "models",
            "events",
            "replay"
    );

    private CoreCli() {}

    public static int main(String[] argv) {
        if (argv == null || argv.length == 0) {
            return 2;
        }
        try {
            String cmd = argv[0];
            return switch (cmd) {
                case "analyze-request" -> handleAnalyzeRequest(argv);
                case "analyze-behavior" -> handleAnalyzeBehavior(argv);
                case "replay" -> handleReplay(argv);
                case "reset" -> handleReset(argv);
                case "list" -> handleList(argv);
                default -> 2;
            };
        } catch (Exception ex) {
            return 1;
        }
    }

    private static int handleAnalyzeRequest(String[] argv) throws Exception {
        String requestPath = optionValue(argv, "--request");
        if (requestPath == null) {
            return 2;
        }
        JsonNode item = MAPPER.readTree(Files.readString(Path.of(requestPath)));
        NormalizedRequestCore req = new NormalizedRequestCore(
                item.path("ip").asText(""),
                item.path("method").asText("GET"),
                item.path("path").asText("/"),
                jsonObjectToStringMap(item.path("headers")),
                item.path("query").asText(""),
                item.path("body").asText(""),
                item.path("known_path").asBoolean(false),
                item.path("exempt_path").asBoolean(false)
        );
        ApiPolicyCore.analyzeRequest(req, List.of(), null, List.of(), List.of(), List.of());
        return 0;
    }

    private static int handleAnalyzeBehavior(String[] argv) throws Exception {
        String eventsPath = optionValue(argv, "--events");
        if (eventsPath == null) {
            return 2;
        }
        List<NormalizedEvent> events = loadEvents(eventsPath);
        TrainingCore.analyzeBehavior(events, List.of(), null, false);
        return 0;
    }

    private static int handleReplay(String[] argv) throws Exception {
        String casesPath = optionValue(argv, "--cases");
        if (casesPath == null) {
            return 2;
        }
        List<ReplayCore.ReplayCase> cases = ReplayCore.loadReplayCases(Path.of(casesPath));
        AiwafConfig config = new AiwafConfig();
        config.methodValidationEnabled = true;
        config.rateLimitEnabled = false;
        config.headerValidationEnabled = false;
        List<String> failures = ReplayCore.assertReplayParity(cases, config);
        return failures.isEmpty() ? 0 : 1;
    }

    private static int handleReset(String[] argv) {
        Set<String> targets = parseTargets(argv);
        if (targets == null) {
            return 2;
        }
        // Core parity reset has no persisted mutable state here, but CLI validates target contract.
        return 0;
    }

    private static int handleList(String[] argv) {
        Set<String> targets = parseTargets(argv);
        if (targets == null) {
            return 2;
        }
        return 0;
    }

    private static String optionValue(String[] argv, String option) {
        for (int i = 0; i < argv.length; i++) {
            if (option.equals(argv[i]) && i + 1 < argv.length) {
                return argv[i + 1];
            }
        }
        return null;
    }

    private static Set<String> parseTargets(String[] argv) {
        String raw = optionValue(argv, "--targets");
        if (raw == null || raw.isBlank()) {
            return Set.of("all");
        }
        Set<String> targets = new HashSet<>();
        String[] parts = raw.split(",");
        for (String part : parts) {
            String target = part == null ? "" : part.trim().toLowerCase();
            if (target.isBlank() || !VALID_TARGETS.contains(target)) {
                return null;
            }
            targets.add(target);
        }
        if (targets.isEmpty()) {
            return null;
        }
        if (targets.contains("all") && targets.size() > 1) {
            return null;
        }
        return targets;
    }

    private static List<NormalizedEvent> loadEvents(String path) throws Exception {
        JsonNode root = MAPPER.readTree(Files.readString(Path.of(path)));
        List<NormalizedEvent> events = new ArrayList<>();
        if (!root.isArray()) {
            return events;
        }
        for (JsonNode item : root) {
            events.add(new NormalizedEvent(
                    item.path("ip").asText(""),
                    item.path("method").asText("GET"),
                    item.path("path").asText("/"),
                    item.path("status_code").asInt(0),
                    item.path("response_time_ms").asDouble(0.0),
                    LocalDateTime.parse(item.path("timestamp").asText()),
                    item.path("user_agent").asText(""),
                    item.path("query").asText(""),
                    item.path("body").asText(""),
                    item.path("known_path").asBoolean(false),
                    item.path("exempt_path").asBoolean(false)
            ));
        }
        return events;
    }

    private static Map<String, String> jsonObjectToStringMap(JsonNode node) {
        Map<String, String> out = new HashMap<>();
        if (node == null || !node.isObject()) {
            return out;
        }
        node.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asText("")));
        return out;
    }
}
