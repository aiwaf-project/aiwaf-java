package com.aiwaf.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CoreCliParityTest {

    @TempDir
    Path tempDir;

    @Test
    void reset_and_list_default_targets_are_valid() {
        assertEquals(0, CoreCli.main(new String[]{"reset"}));
        assertEquals(0, CoreCli.main(new String[]{"list"}));
    }

    @Test
    void reset_and_list_reject_invalid_targets() {
        assertEquals(2, CoreCli.main(new String[]{"reset", "--targets", "bad"}));
        assertEquals(2, CoreCli.main(new String[]{"list", "--targets", "all,features"}));
        assertEquals(2, CoreCli.main(new String[]{"list", "--targets", ","}));
    }

    @Test
    void replay_requires_cases_option() {
        assertEquals(2, CoreCli.main(new String[]{"replay"}));
        assertEquals(2, CoreCli.main(new String[]{"replay", "--cases"}));
    }

    @Test
    void analyze_behavior_requires_events_option() {
        assertEquals(2, CoreCli.main(new String[]{"analyze-behavior"}));
        assertEquals(2, CoreCli.main(new String[]{"analyze-behavior", "--events"}));
    }

    @Test
    void analyze_request_requires_request_option() {
        assertEquals(2, CoreCli.main(new String[]{"analyze-request"}));
        assertEquals(2, CoreCli.main(new String[]{"analyze-request", "--request"}));
    }

    @Test
    void analyze_request_with_invalid_json_returns_error() throws Exception {
        Path reqJson = tempDir.resolve("bad.json");
        Files.writeString(reqJson, "{", StandardCharsets.UTF_8);
        assertEquals(1, CoreCli.main(new String[]{"analyze-request", "--request", reqJson.toString()}));
    }

    @Test
    void unknown_command_returns_usage_error() {
        assertEquals(2, CoreCli.main(new String[]{"unknown"}));
    }
}
