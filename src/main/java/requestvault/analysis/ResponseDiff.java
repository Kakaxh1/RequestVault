package requestvault.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import requestvault.model.TrafficRecord;
import requestvault.security.HashService;

import java.util.*;

/**
 * High-performance, side-by-side and unified HTTP response difference engine.
 * Computes status, headers, line-by-line body diffs with alignment,
 * JSONPath field differences, binary safety, and non-judgmental security observations.
 */
public class ResponseDiff {

    public enum DiffType {
        UNCHANGED,
        ADDED,
        REMOVED,
        MODIFIED
    }

    public static class HeaderDiff {
        private final String name;
        private final DiffType type;
        private final String valueA;
        private final String valueB;
        private final boolean securityRelevant;

        public HeaderDiff(String name, DiffType type, String valueA, String valueB, boolean securityRelevant) {
            this.name = name;
            this.type = type;
            this.valueA = valueA != null ? valueA : "";
            this.valueB = valueB != null ? valueB : "";
            this.securityRelevant = securityRelevant;
        }

        public String getName() { return name; }
        public DiffType getType() { return type; }
        public String getValueA() { return valueA; }
        public String getValueB() { return valueB; }
        public boolean isSecurityRelevant() { return securityRelevant; }
    }

    public static class DiffRow {
        private final int lineNumA;
        private final String textA;
        private final int lineNumB;
        private final String textB;
        private final DiffType type;
        private final String inlineDiff;

        public DiffRow(int lineNumA, String textA, int lineNumB, String textB, DiffType type, String inlineDiff) {
            this.lineNumA = lineNumA;
            this.textA = textA != null ? textA : "";
            this.lineNumB = lineNumB;
            this.textB = textB != null ? textB : "";
            this.type = type;
            this.inlineDiff = inlineDiff;
        }

        public int getLineNumA() { return lineNumA; }
        public String getTextA() { return textA; }
        public int getLineNumB() { return lineNumB; }
        public String getTextB() { return textB; }
        public DiffType getType() { return type; }
        public String getInlineDiff() { return inlineDiff; }
        public boolean isDifferent() { return type != DiffType.UNCHANGED; }
    }

    public static class JsonFieldDiff {
        private final String path;
        private final DiffType type;
        private final String valueA;
        private final String valueB;
        private final boolean securityRelevant;

        public JsonFieldDiff(String path, DiffType type, String valueA, String valueB, boolean securityRelevant) {
            this.path = path;
            this.type = type;
            this.valueA = valueA != null ? valueA : "";
            this.valueB = valueB != null ? valueB : "";
            this.securityRelevant = securityRelevant;
        }

        public String getPath() { return path; }
        public DiffType getType() { return type; }
        public String getValueA() { return valueA; }
        public String getValueB() { return valueB; }
        public boolean isSecurityRelevant() { return securityRelevant; }
    }

    public static class SecurityObservation {
        private final String category;
        private final String description;

        public SecurityObservation(String category, String description) {
            this.category = category;
            this.description = description;
        }

        public String getCategory() { return category; }
        public String getDescription() { return description; }
    }

    public static class DiffReport {
        public TrafficRecord recordA;
        public TrafficRecord recordB;

        public boolean hasResponseA;
        public boolean hasResponseB;

        public int statusA;
        public int statusB;
        public String statusReasonA = "";
        public String statusReasonB = "";
        public boolean statusMatch;

        public int sizeA;
        public int sizeB;
        public int sizeDiff;
        public double sizePercentDelta;

        public String mimeA = "";
        public String mimeB = "";
        public boolean isBinaryA;
        public boolean isBinaryB;
        public String hashA = "";
        public String hashB = "";

        public boolean isJsonA;
        public boolean isJsonB;

        public List<HeaderDiff> headerDiffs = new ArrayList<>();
        public List<DiffRow> bodyDiffRows = new ArrayList<>();
        public List<String> unifiedDiffLines = new ArrayList<>();
        public List<JsonFieldDiff> jsonDiffs = new ArrayList<>();
        public List<SecurityObservation> securityObservations = new ArrayList<>();

        public int totalDiffRows;
        public int addedLinesCount;
        public int removedLinesCount;
        public int modifiedLinesCount;
        public boolean isTruncated;
    }

    public static DiffReport compare(TrafficRecord a, TrafficRecord b) {
        DiffReport report = new DiffReport();
        report.recordA = a;
        report.recordB = b;

        if (a == null || b == null) {
            return report;
        }

        report.hasResponseA = a.hasResponse();
        report.hasResponseB = b.hasResponse();

        // 1. Status comparison
        if (report.hasResponseA) {
            report.statusA = a.getStatusCode();
            report.statusReasonA = a.getStatusReason() != null ? a.getStatusReason() : "";
        }
        if (report.hasResponseB) {
            report.statusB = b.getStatusCode();
            report.statusReasonB = b.getStatusReason() != null ? b.getStatusReason() : "";
        }
        report.statusMatch = (report.statusA == report.statusB) && (report.hasResponseA == report.hasResponseB);

        // Security observation: Status transition
        if (report.hasResponseA && report.hasResponseB && !report.statusMatch) {
            if ((report.statusA == 200 && (report.statusB == 401 || report.statusB == 403))
                    || ((report.statusA == 401 || report.statusA == 403) && report.statusB == 200)) {
                report.securityObservations.add(new SecurityObservation("Access Control",
                        String.format("Status transition between %d (%s) and %d (%s) observed.",
                                report.statusA, report.statusReasonA, report.statusB, report.statusReasonB)));
            } else if (report.statusA == 500 || report.statusB == 500) {
                report.securityObservations.add(new SecurityObservation("Error Handling",
                        String.format("Server error status 500 observed (%d vs %d).", report.statusA, report.statusB)));
            } else if (isRedirect(report.statusA) != isRedirect(report.statusB)) {
                report.securityObservations.add(new SecurityObservation("Redirection",
                        String.format("Redirection status change observed (%d vs %d).", report.statusA, report.statusB)));
            }
        }

        // 2. Size comparison
        report.sizeA = a.getResponseSize();
        report.sizeB = b.getResponseSize();
        report.sizeDiff = report.sizeB - report.sizeA;
        if (report.sizeA > 0) {
            report.sizePercentDelta = ((double) report.sizeDiff / (double) report.sizeA) * 100.0;
        }

        if (Math.abs(report.sizeDiff) > 50000 || (report.sizeA > 0 && Math.abs(report.sizePercentDelta) > 200.0)) {
            report.securityObservations.add(new SecurityObservation("Response Size Delta",
                    String.format("Substantial size difference: A=%d bytes, B=%d bytes (Δ %+d bytes, %.1f%%).",
                            report.sizeA, report.sizeB, report.sizeDiff, report.sizePercentDelta)));
        }

        // 3. MIME and Binary Detection
        byte[] bodyBytesA = a.getResponseBodyBytes();
        byte[] bodyBytesB = b.getResponseBodyBytes();

        report.mimeA = a.getContentType() != null ? a.getContentType() : "";
        report.mimeB = b.getContentType() != null ? b.getContentType() : "";

        report.isBinaryA = isBinaryData(bodyBytesA, report.mimeA);
        report.isBinaryB = isBinaryData(bodyBytesB, report.mimeB);

        report.hashA = HashService.sha256(bodyBytesA);
        report.hashB = HashService.sha256(bodyBytesB);

        // 4. Headers comparison
        compareHeaders(a, b, report);

        // 5. Body comparison
        if (report.isBinaryA || report.isBinaryB) {
            handleBinaryComparison(report);
        } else {
            handleTextAndJsonComparison(a, b, report);
        }

        // Calculate diff counts
        for (DiffRow row : report.bodyDiffRows) {
            if (row.isDifferent()) {
                report.totalDiffRows++;
                if (row.getType() == DiffType.ADDED) report.addedLinesCount++;
                else if (row.getType() == DiffType.REMOVED) report.removedLinesCount++;
                else if (row.getType() == DiffType.MODIFIED) report.modifiedLinesCount++;
            }
        }

        return report;
    }

    private static boolean isRedirect(int status) {
        return status >= 300 && status < 400;
    }

    private static boolean isBinaryData(byte[] data, String contentType) {
        if (data == null || data.length == 0) return false;
        String ct = contentType.toLowerCase();
        if (ct.contains("image/") || ct.contains("audio/") || ct.contains("video/") || ct.contains("application/octet-stream")
                || ct.contains("application/zip") || ct.contains("application/pdf") || ct.contains("application/gzip")) {
            return true;
        }
        int checkLen = Math.min(data.length, 1024);
        int nonPrintable = 0;
        for (int i = 0; i < checkLen; i++) {
            byte b = data[i];
            if (b == 0) return true; // null byte is characteristic of binary
            if ((b < 32 && b != 9 && b != 10 && b != 13) || (b & 0xFF) == 0xFF) {
                nonPrintable++;
            }
        }
        return (double) nonPrintable / checkLen > 0.25;
    }

    private static void compareHeaders(TrafficRecord a, TrafficRecord b, DiffReport report) {
        List<String> headersA = a.getResponseHeaders();
        List<String> headersB = b.getResponseHeaders();

        Map<String, String> mapA = new LinkedHashMap<>();
        for (String h : headersA) {
            int idx = h.indexOf(':');
            if (idx > 0) {
                String k = h.substring(0, idx).trim();
                String v = h.substring(idx + 1).trim();
                mapA.put(k, v);
            }
        }

        Map<String, String> mapB = new LinkedHashMap<>();
        for (String h : headersB) {
            int idx = h.indexOf(':');
            if (idx > 0) {
                String k = h.substring(0, idx).trim();
                String v = h.substring(idx + 1).trim();
                mapB.put(k, v);
            }
        }

        Set<String> processedKeys = new HashSet<>();

        for (Map.Entry<String, String> entryA : mapA.entrySet()) {
            String key = entryA.getKey();
            String valA = entryA.getValue();
            processedKeys.add(key.toLowerCase());

            String keyB = findKeyCaseInsensitive(mapB, key);
            boolean secRel = isSecurityHeader(key);

            if (keyB == null) {
                report.headerDiffs.add(new HeaderDiff(key, DiffType.REMOVED, valA, "", secRel));
                if (secRel) {
                    report.securityObservations.add(new SecurityObservation("Security Header Removed",
                            String.format("Header '%s' present in Response A but missing in Response B.", key)));
                }
            } else {
                String valB = mapB.get(keyB);
                if (!valA.equals(valB)) {
                    report.headerDiffs.add(new HeaderDiff(key, DiffType.MODIFIED, valA, valB, secRel));
                    if (secRel) {
                        report.securityObservations.add(new SecurityObservation("Security Header Modified",
                                String.format("Header '%s' value changed: '%s' → '%s'", key, valA, valB)));
                    }
                } else {
                    report.headerDiffs.add(new HeaderDiff(key, DiffType.UNCHANGED, valA, valB, false));
                }
            }
        }

        for (Map.Entry<String, String> entryB : mapB.entrySet()) {
            String key = entryB.getKey();
            if (!processedKeys.contains(key.toLowerCase())) {
                boolean secRel = isSecurityHeader(key);
                report.headerDiffs.add(new HeaderDiff(key, DiffType.ADDED, "", entryB.getValue(), secRel));
                if (secRel) {
                    report.securityObservations.add(new SecurityObservation("Security Header Added",
                            String.format("Header '%s' added in Response B: '%s'", key, entryB.getValue())));
                }
            }
        }
    }

    private static String findKeyCaseInsensitive(Map<String, String> map, String key) {
        for (String k : map.keySet()) {
            if (k.equalsIgnoreCase(key)) return k;
        }
        return null;
    }

    private static boolean isSecurityHeader(String header) {
        String h = header.toLowerCase();
        return h.contains("set-cookie") || h.contains("authorization") || h.contains("access-control")
                || h.contains("content-security-policy") || h.contains("x-frame-options")
                || h.contains("x-content-type-options") || h.contains("strict-transport-security")
                || h.contains("location") || h.contains("www-authenticate");
    }

    private static void handleBinaryComparison(DiffReport report) {
        String textA = String.format("[Binary Content: %d bytes | SHA-256: %s]", report.sizeA, report.hashA);
        String textB = String.format("[Binary Content: %d bytes | SHA-256: %s]", report.sizeB, report.hashB);

        DiffType type = report.hashA.equals(report.hashB) ? DiffType.UNCHANGED : DiffType.MODIFIED;
        report.bodyDiffRows.add(new DiffRow(1, textA, 1, textB, type, null));

        if (type == DiffType.MODIFIED) {
            report.unifiedDiffLines.add("- " + textA);
            report.unifiedDiffLines.add("+ " + textB);
        } else {
            report.unifiedDiffLines.add("  " + textA);
        }
    }

    private static void handleTextAndJsonComparison(TrafficRecord a, TrafficRecord b, DiffReport report) {
        String bodyA = a.hasResponse() ? a.getResponseBodyAsString() : "[No Response Recorded]";
        String bodyB = b.hasResponse() ? b.getResponseBodyAsString() : "[No Response Recorded]";

        // 1. JSON analysis if applicable
        JsonElement jsonElementA = tryParseJson(bodyA);
        JsonElement jsonElementB = tryParseJson(bodyB);

        report.isJsonA = (jsonElementA != null);
        report.isJsonB = (jsonElementB != null);

        if (report.isJsonA && report.isJsonB) {
            compareJsonElements("$", jsonElementA, jsonElementB, report);
        }

        // 2. Line-by-line Diffing with LCS alignment
        String[] linesA = bodyA.split("\\r?\\n", -1);
        String[] linesB = bodyB.split("\\r?\\n", -1);

        // Cap very large responses to prevent UI freeze
        final int MAX_LINES = 10000;
        if (linesA.length > MAX_LINES || linesB.length > MAX_LINES) {
            report.isTruncated = true;
            if (linesA.length > MAX_LINES) linesA = Arrays.copyOf(linesA, MAX_LINES);
            if (linesB.length > MAX_LINES) linesB = Arrays.copyOf(linesB, MAX_LINES);
        }

        computeAlignedLineDiff(linesA, linesB, report);
    }

    private static JsonElement tryParseJson(String text) {
        if (text == null) return null;
        String trimmed = text.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                return JsonParser.parseString(trimmed);
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static void compareJsonElements(String path, JsonElement elA, JsonElement elB, DiffReport report) {
        if (elA.isJsonObject() && elB.isJsonObject()) {
            JsonObject objA = elA.getAsJsonObject();
            JsonObject objB = elB.getAsJsonObject();

            Set<String> allKeys = new LinkedHashSet<>(objA.keySet());
            allKeys.addAll(objB.keySet());

            for (String key : allKeys) {
                String currentPath = path.equals("$") ? "$." + key : path + "." + key;
                boolean inA = objA.has(key);
                boolean inB = objB.has(key);

                if (inA && inB) {
                    compareJsonElements(currentPath, objA.get(key), objB.get(key), report);
                } else if (inA) {
                    boolean secRel = isSecurityProperty(key);
                    report.jsonDiffs.add(new JsonFieldDiff(currentPath, DiffType.REMOVED, objA.get(key).toString(), "", secRel));
                    if (secRel) {
                        report.securityObservations.add(new SecurityObservation("JSON Field Removed",
                                String.format("Field '%s' with value '%s' removed in Response B.", currentPath, objA.get(key))));
                    }
                } else {
                    boolean secRel = isSecurityProperty(key);
                    report.jsonDiffs.add(new JsonFieldDiff(currentPath, DiffType.ADDED, "", objB.get(key).toString(), secRel));
                    if (secRel) {
                        report.securityObservations.add(new SecurityObservation("JSON Field Added",
                                String.format("Field '%s' with value '%s' added in Response B.", currentPath, objB.get(key))));
                    }
                }
            }
        } else if (elA.isJsonArray() && elB.isJsonArray()) {
            JsonArray arrA = elA.getAsJsonArray();
            JsonArray arrB = elB.getAsJsonArray();
            int max = Math.max(arrA.size(), arrB.size());
            for (int i = 0; i < max; i++) {
                String currentPath = path + "[" + i + "]";
                if (i < arrA.size() && i < arrB.size()) {
                    compareJsonElements(currentPath, arrA.get(i), arrB.get(i), report);
                } else if (i < arrA.size()) {
                    report.jsonDiffs.add(new JsonFieldDiff(currentPath, DiffType.REMOVED, arrA.get(i).toString(), "", false));
                } else {
                    report.jsonDiffs.add(new JsonFieldDiff(currentPath, DiffType.ADDED, "", arrB.get(i).toString(), false));
                }
            }
        } else {
            String valA = elA.toString();
            String valB = elB.toString();
            if (!valA.equals(valB)) {
                boolean secRel = isSecurityProperty(path);
                report.jsonDiffs.add(new JsonFieldDiff(path, DiffType.MODIFIED, valA, valB, secRel));
                if (secRel) {
                    report.securityObservations.add(new SecurityObservation("JSON Security Value Changed",
                            String.format("Field '%s' changed: %s → %s", path, valA, valB)));
                }
            }
        }
    }

    private static boolean isSecurityProperty(String prop) {
        String p = prop.toLowerCase();
        return p.contains("role") || p.contains("admin") || p.contains("privilege") || p.contains("auth")
                || p.contains("token") || p.contains("secret") || p.contains("permission") || p.contains("scope")
                || p.contains("user_id") || p.contains("userid") || p.contains("email") || p.contains("password")
                || p.contains("debug") || p.contains("is_admin") || p.contains("isadmin");
    }

    /**
     * Computes side-by-side aligned line difference using Longest Common Subsequence (LCS).
     */
    private static void computeAlignedLineDiff(String[] linesA, String[] linesB, DiffReport report) {
        int m = linesA.length;
        int n = linesB.length;

        // LCS matrix
        int[][] lcs = new int[m + 1][n + 1];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < n; j++) {
                if (linesA[i].equals(linesB[j])) {
                    lcs[i + 1][j + 1] = lcs[i][j] + 1;
                } else {
                    lcs[i + 1][j + 1] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
                }
            }
        }

        // Backtrack to find aligned operations
        List<RawDiffItem> rawItems = new ArrayList<>();
        int i = m, j = n;
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && linesA[i - 1].equals(linesB[j - 1])) {
                rawItems.add(new RawDiffItem(DiffType.UNCHANGED, i, linesA[i - 1], j, linesB[j - 1]));
                i--;
                j--;
            } else if (j > 0 && (i == 0 || lcs[i][j - 1] >= lcs[i - 1][j])) {
                rawItems.add(new RawDiffItem(DiffType.ADDED, -1, null, j, linesB[j - 1]));
                j--;
            } else if (i > 0) {
                rawItems.add(new RawDiffItem(DiffType.REMOVED, i, linesA[i - 1], -1, null));
                i--;
            }
        }
        Collections.reverse(rawItems);

        // Post-process: Pairwise chunk alignment for side-by-side diffing
        int idx = 0;
        while (idx < rawItems.size()) {
            RawDiffItem cur = rawItems.get(idx);

            if (cur.type == DiffType.UNCHANGED) {
                report.bodyDiffRows.add(new DiffRow(cur.lineA, cur.textA, cur.lineB, cur.textB, DiffType.UNCHANGED, null));
                report.unifiedDiffLines.add("  " + cur.textA);
                idx++;
            } else {
                List<RawDiffItem> chunkRemoved = new ArrayList<>();
                List<RawDiffItem> chunkAdded = new ArrayList<>();

                while (idx < rawItems.size() && rawItems.get(idx).type != DiffType.UNCHANGED) {
                    RawDiffItem item = rawItems.get(idx);
                    if (item.type == DiffType.REMOVED) {
                        chunkRemoved.add(item);
                    } else {
                        chunkAdded.add(item);
                    }
                    idx++;
                }

                int pairs = Math.min(chunkRemoved.size(), chunkAdded.size());
                for (int p = 0; p < pairs; p++) {
                    RawDiffItem rem = chunkRemoved.get(p);
                    RawDiffItem add = chunkAdded.get(p);
                    String inline = computeInlineDiff(rem.textA, add.textB);
                    report.bodyDiffRows.add(new DiffRow(rem.lineA, rem.textA, add.lineB, add.textB, DiffType.MODIFIED, inline));
                }
                for (int p = pairs; p < chunkRemoved.size(); p++) {
                    RawDiffItem rem = chunkRemoved.get(p);
                    report.bodyDiffRows.add(new DiffRow(rem.lineA, rem.textA, 0, "", DiffType.REMOVED, null));
                }
                for (int p = pairs; p < chunkAdded.size(); p++) {
                    RawDiffItem add = chunkAdded.get(p);
                    report.bodyDiffRows.add(new DiffRow(0, "", add.lineB, add.textB, DiffType.ADDED, null));
                }

                // Add to unified diff
                for (RawDiffItem rem : chunkRemoved) {
                    report.unifiedDiffLines.add("- " + rem.textA);
                }
                for (RawDiffItem add : chunkAdded) {
                    report.unifiedDiffLines.add("+ " + add.textB);
                }
            }
        }
    }

    private static String computeInlineDiff(String a, String b) {
        if (a == null || b == null) return null;
        if (a.equals(b)) return null;

        // Word/token-level diffing for human-readable changes
        String[] wordsA = a.split("(?<=[\\s,:\"'\\[\\]{}])|(?=[\\s,:\"'\\[\\]{}])");
        String[] wordsB = b.split("(?<=[\\s,:\"'\\[\\]{}])|(?=[\\s,:\"'\\[\\]{}])");

        int start = 0;
        while (start < wordsA.length && start < wordsB.length && wordsA[start].equals(wordsB[start])) {
            start++;
        }

        int endA = wordsA.length - 1;
        int endB = wordsB.length - 1;
        while (endA >= start && endB >= start && wordsA[endA].equals(wordsB[endB])) {
            endA--;
            endB--;
        }

        StringBuilder diffA = new StringBuilder();
        for (int k = start; k <= endA; k++) diffA.append(wordsA[k]);

        StringBuilder diffB = new StringBuilder();
        for (int k = start; k <= endB; k++) diffB.append(wordsB[k]);

        String strA = diffA.toString().trim();
        String strB = diffB.toString().trim();

        if (strA.isEmpty() && strB.isEmpty()) return null;
        return String.format("'%s' → '%s'", strA, strB);
    }

    private static class RawDiffItem {
        final DiffType type;
        final int lineA;
        final String textA;
        final int lineB;
        final String textB;

        RawDiffItem(DiffType type, int lineA, String textA, int lineB, String textB) {
            this.type = type;
            this.lineA = lineA;
            this.textA = textA;
            this.lineB = lineB;
            this.textB = textB;
        }
    }
}
