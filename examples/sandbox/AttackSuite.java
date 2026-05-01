import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class AttackSuite {
    private static final String[] ATTACK_PATHS = new String[]{
            "/admin.php",
            "/wp-admin",
            "/.env",
            "/.git/config",
            "/xmlrpc.php",
            "/api/users?uuid=not-a-uuid"
    };

    private static final String[] NORMAL_PATHS = new String[]{
            "/",
            "/rest/products/search?q=apple",
            "/rest/user/whoami"
    };

    public static void main(String[] args) throws Exception {
        String baseUrl = args.length > 0 ? trimSlash(args[0]) : "http://127.0.0.1:3001";
        String label = args.length > 1 ? sanitizeLabel(args[1]) : "direct";
        String mode = args.length > 2 ? normalizeMode(args[2]) : "attacks";

        List<Result> results = new ArrayList<>();

        String[] paths = switch (mode) {
            case "normal" -> NORMAL_PATHS;
            case "all" -> concat(NORMAL_PATHS, ATTACK_PATHS);
            default -> ATTACK_PATHS;
        };

        for (String path : paths) {
            String fullUrl = baseUrl + path;
            long startNanos = System.nanoTime();
            HttpRequest request = HttpRequest.newBuilder(URI.create(fullUrl))
                    .timeout(java.time.Duration.ofSeconds(10))
                    .GET()
                    .header("User-Agent", mode.equals("attacks") || mode.equals("all") ? "sqlmap/1.0" : "Mozilla/5.0")
                    .header("Accept", "*/*")
                    .build();

            try {
                HttpResponse<String> response = sendWithRetry(request);
                long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
                results.add(new Result(path, response.statusCode(), true, elapsedMs, ""));
            } catch (IOException | InterruptedException ex) {
                long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
                results.add(new Result(path, 0, false, elapsedMs, ex.getClass().getSimpleName() + ": " + safeMessage(ex)));
            }
        }

        String timestamp = Instant.now().toString().replace(':', '-');
        String output = "results_" + label + "_" + mode + "_" + timestamp + ".json";
        Files.writeString(Path.of(output), toJson(baseUrl, label, mode, results), StandardCharsets.UTF_8);
        System.out.println("Wrote " + output + " (" + results.size() + " requests)");
    }

    private static String toJson(String baseUrl, String label, String mode, List<Result> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"base_url\": \"").append(escape(baseUrl)).append("\",\n");
        sb.append("  \"label\": \"").append(escape(label)).append("\",\n");
        sb.append("  \"mode\": \"").append(escape(mode)).append("\",\n");
        sb.append("  \"results\": [\n");

        for (int i = 0; i < results.size(); i++) {
            Result r = results.get(i);
            sb.append("    {")
                    .append("\"path\":\"").append(escape(r.path)).append("\",")
                    .append("\"status\":").append(r.status).append(",")
                    .append("\"ok\":").append(r.ok).append(",")
                    .append("\"elapsed_ms\":").append(r.elapsedMs).append(",")
                    .append("\"error\":\"").append(escape(r.error)).append("\"")
                    .append("}");
            if (i < results.size() - 1) {
                sb.append(',');
            }
            sb.append('\n');
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String[] concat(String[] a, String[] b) {
        String[] out = new String[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String sanitizeLabel(String label) {
        return label == null ? "run" : label.toLowerCase().replaceAll("[^a-z0-9_-]+", "_");
    }

    private static String normalizeMode(String mode) {
        if (mode == null) {
            return "attacks";
        }
        String m = mode.toLowerCase();
        if (m.equals("normal") || m.equals("all") || m.equals("attacks")) {
            return m;
        }
        return "attacks";
    }

    private static String trimSlash(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return "http://127.0.0.1:3001";
        }
        return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    private static String safeMessage(Exception ex) {
        String msg = ex.getMessage();
        return msg == null ? "" : msg;
    }


    private static HttpResponse<String> sendWithRetry(HttpRequest request) throws IOException, InterruptedException {
        IOException lastIo = null;
        for (int i = 0; i < 2; i++) {
            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(java.time.Duration.ofSeconds(5))
                    .build();
            try {
                return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (IOException ioe) {
                lastIo = ioe;
            }
        }
        throw lastIo == null ? new IOException("request failed") : lastIo;
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private record Result(String path, int status, boolean ok, long elapsedMs, String error) {}
}
