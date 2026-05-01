import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CompareResults {
    private static final Pattern STATUS_PATTERN = Pattern.compile("\"status\"\\s*:\\s*(\\d+)");
    private static final Pattern LABEL_PATTERN = Pattern.compile("\"label\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern MODE_PATTERN = Pattern.compile("\"mode\"\\s*:\\s*\"([^\"]*)\"");

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage: java CompareResults <result-file-or-glob> [<result-file-or-glob> ...]");
            return;
        }

        List<Path> files = expandInputs(args);
        if (files.isEmpty()) {
            System.out.println("No result files matched.");
            return;
        }

        Totals all = new Totals();

        for (Path file : files) {
            String body = Files.readString(file, StandardCharsets.UTF_8);
            Parsed parsed = parse(body);
            all.merge(parsed.totals);

            System.out.printf(
                    "%s [%s/%s] -> total=%d blocked=%d (403=%d,429=%d) allowed2xx=%d errors=%d other=%d%n",
                    file.getFileName(),
                    parsed.label,
                    parsed.mode,
                    parsed.totals.total,
                    parsed.totals.blocked(),
                    parsed.totals.status403,
                    parsed.totals.status429,
                    parsed.totals.allowed2xx,
                    parsed.totals.error,
                    parsed.totals.other
            );
        }

        System.out.printf(
                "ALL -> total=%d blocked=%d (%.1f%%) allowed2xx=%d errors=%d other=%d%n",
                all.total,
                all.blocked(),
                all.total == 0 ? 0.0 : (100.0 * all.blocked() / all.total),
                all.allowed2xx,
                all.error,
                all.other
        );
    }

    private static Parsed parse(String body) {
        Totals t = new Totals();

        Matcher statuses = STATUS_PATTERN.matcher(body);
        while (statuses.find()) {
            t.total++;
            int code = Integer.parseInt(statuses.group(1));
            if (code == 403) {
                t.status403++;
            } else if (code == 429) {
                t.status429++;
            } else if (code >= 200 && code < 300) {
                t.allowed2xx++;
            } else if (code == 0 || code >= 500) {
                t.error++;
            } else {
                t.other++;
            }
        }

        String label = findOne(body, LABEL_PATTERN, "unknown");
        String mode = findOne(body, MODE_PATTERN, "unknown");
        return new Parsed(label, mode, t);
    }

    private static String findOne(String body, Pattern pattern, String fallback) {
        Matcher m = pattern.matcher(body);
        return m.find() ? m.group(1) : fallback;
    }

    private static List<Path> expandInputs(String[] args) throws IOException {
        List<Path> out = new ArrayList<>();
        for (String arg : args) {
            out.addAll(expandOne(arg));
        }
        out.sort(Comparator.comparing(Path::toString));
        return out;
    }

    private static List<Path> expandOne(String raw) throws IOException {
        List<Path> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            return out;
        }

        boolean hasWildcard = raw.contains("*") || raw.contains("?") || raw.contains("[");
        Path path = Paths.get(raw);

        if (!hasWildcard) {
            if (Files.exists(path) && Files.isRegularFile(path)) {
                out.add(path);
            }
            return out;
        }

        Path dir = path.getParent() == null ? Paths.get(".") : path.getParent();
        String pattern = path.getFileName().toString();

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, pattern)) {
            for (Path p : stream) {
                if (Files.isRegularFile(p)) {
                    out.add(p);
                }
            }
        }
        return out;
    }

    private static final class Totals {
        int total;
        int status403;
        int status429;
        int allowed2xx;
        int error;
        int other;

        int blocked() {
            return status403 + status429;
        }

        void merge(Totals otherTotals) {
            total += otherTotals.total;
            status403 += otherTotals.status403;
            status429 += otherTotals.status429;
            allowed2xx += otherTotals.allowed2xx;
            error += otherTotals.error;
            other += otherTotals.other;
        }
    }

    private record Parsed(String label, String mode, Totals totals) {}
}
