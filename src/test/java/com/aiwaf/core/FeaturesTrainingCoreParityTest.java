package com.aiwaf.core;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeaturesTrainingCoreParityTest {

    private static List<NormalizedEvent> events() {
        LocalDateTime ts = LocalDateTime.of(2026, 1, 1, 0, 0);
        return List.of(
                new NormalizedEvent("1.1.1.1", "GET", "/api/login", 200, 10, ts, "", "", "", true, false),
                new NormalizedEvent("1.1.1.1", "POST", "/wp-admin/shell-login", 404, 25, ts, "", "", "", false, false),
                new NormalizedEvent("1.1.1.2", "GET", "/wp-admin/shell-login", 404, 15, ts, "", "", "", false, false)
        );
    }

    @Test
    void feature_extraction_is_deterministic() {
        List<FeatureVectorCore> first = FeaturesCore.extractFeatures(events(), Set.of());
        List<FeatureVectorCore> second = FeaturesCore.extractFeatures(events(), Set.of());
        assertEquals(first, second);
        assertEquals(1.0, first.get(1).values().get("method_is_post"));
    }

    @Test
    void dynamic_keyword_learning() {
        List<String> learned = FeaturesCore.extractKeywordsFromEvents(events(), new FeaturesCore.KeywordLearningConfig());
        assertTrue(learned.contains("shell-login") || learned.contains("shell"));
    }

    @Test
    void training_returns_model_payload() {
        TrainedModelCore model = TrainingCore.trainModel(events(), List.of());
        assertEquals("isolation-forest", model.modelType());
        assertEquals(3, ((Number) model.payload().get("samples")).intValue());
        assertTrue(model.payload().containsKey("behavior"));
        assertTrue(model.payload().containsKey("isolation_forest"));
    }

    @Test
    void behavior_analysis_summary() {
        Map<String, Object> summary = TrainingCore.analyzeBehavior(events(), List.of(), null, false);
        Map<?, ?> requestsPerIp = (Map<?, ?>) summary.get("requests_per_ip");
        assertEquals(2, ((Number) requestsPerIp.get("1.1.1.1")).intValue());
        Map<?, ?> methodRatio = (Map<?, ?>) summary.get("method_ratio");
        assertTrue(methodRatio.containsKey("POST"));
        assertTrue(summary.containsKey("ip_stats"));
    }
}
