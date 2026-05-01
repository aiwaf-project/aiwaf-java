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

public final class CompareResultsModes {
    private static final Pattern STATUS_PATTERN = Pattern.compile("\"status\"\\s*:\\s*(\\d+)");

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage:");
            System.out.println("  java CompareResultsModes <normal-files...> -- <attacks-files...>");
            System.out.println("  java CompareResultsModes <normal-file-or-glob> <attacks-file-or-glob>");
            return;
        }

        InputGroups groups = splitArgs(args);
        List<Path> normalFiles = expandInputs(groups.normalArgs);
        List<Path> attackFiles = expandInputs(groups.attackArgs);

        if (normalFiles.isEmpty() || attackFiles.isEmpty()) {
            System.out.println("Need at least one normal file and one attacks file.");
            return;
        }

        Totals normal = summarize(normalFiles);
        Totals attacks = summarize(attackFiles);

        System.out.printf("normal files=%d total=%d blocked=%d (%.1f%%) allowed2xx=%d errors=%d other=%d%n",
                normalFiles.size(), normal.total, normal.blocked(), normal.blockRate(), normal.allowed2xx, normal.error, normal.other);

        System.out.printf("attacks files=%d total=%d blocked=%d (%.1f%%) allowed2xx=%d errors=%d other=%d%n",
                attackFiles.size(), attacks.total, attacks.blocked(), attacks.blockRate(), attacks.allowed2xx, attacks.error, attacks.other);

        double delta = attacks.blockRate() - normal.blockRate();
        System.out.printf("delta blocked rate (attacks - normal): %.1f%%%n", delta);
    }

    private static Totals summarize(List<Path> files) throws IOException {
        Totals totals = new Totals();
        for (Path file : files) {
            String body = Files.readString(file, StandardCharsets.UTF_8);
            Matcher statuses = STATUS_PATTERN.matcher(body);
            while (statuses.find()) {
                totals.total++;
                int code = Integer.parseInt(statuses.group(1));
                if (code == 403) {
                    totals.status403++;
                } else if (code == 429) {
                    totals.status429++;
                } else if (code >= 200 && code < 300) {
                    totals.allowed2xx++;
                } else if (code == 0 || code >= 500) {
                    totals.error++;
                } else {
                    totals.other++;
                }
            }
        }
        return totals;
    }

    private static InputGroups splitArgs(String[] args) {
        int sep = -1;
        for (int i = 0; i < args.length; i++) {
            if ("--".equals(args[i])) {
                sep = i;
                break;
            }
        }

        if (sep < 0) {
            return new InputGroups(List.of(args[0]), List.of(args[1]));
        }

        List<String> normal = new ArrayList<>();
        List<String> attacks = new ArrayList<>();

        for (int i = 0; i < sep; i++) {
            normal.add(args[i]);
        }
        for (int i = sep + 1; i < args.length; i++) {
            attacks.add(args[i]);
        }

        return new InputGroups(normal, attacks);
    }

    private static List<Path> expandInputs(List<String> args) throws IOException {
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

        double blockRate() {
            return total == 0 ? 0.0 : (100.0 * blocked() / total);
        }
    }

    private record InputGroups(List<String> normalArgs, List<String> attackArgs) {}
}
