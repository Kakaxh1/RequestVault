package requestvault.analysis;

import requestvault.model.TrafficRecord;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ResponseDiff {

    public static class DiffReport {
        public int statusA;
        public int statusB;
        public boolean statusMatch;

        public int sizeA;
        public int sizeB;
        public int sizeDiff;

        public List<String> headersOnlyInA = new ArrayList<>();
        public List<String> headersOnlyInB = new ArrayList<>();
        public List<String> headerModifications = new ArrayList<>();

        public List<String> bodyDiffLines = new ArrayList<>();
    }

    public static DiffReport compare(TrafficRecord a, TrafficRecord b) {
        DiffReport report = new DiffReport();
        if (a == null || b == null) return report;

        report.statusA = a.getStatusCode();
        report.statusB = b.getStatusCode();
        report.statusMatch = (report.statusA == report.statusB);

        report.sizeA = a.getResponseSize();
        report.sizeB = b.getResponseSize();
        report.sizeDiff = report.sizeB - report.sizeA;

        // Headers comparison
        List<String> hA = a.getResponseHeaders();
        List<String> hB = b.getResponseHeaders();

        for (String ha : hA) {
            String nameA = getHeaderName(ha);
            if (nameA.isEmpty()) continue;
            String matchingB = findHeader(hB, nameA);
            if (matchingB == null) {
                report.headersOnlyInA.add(ha);
            } else if (!ha.trim().equalsIgnoreCase(matchingB.trim())) {
                report.headerModifications.add("A: " + ha + "  |  B: " + matchingB);
            }
        }

        for (String hb : hB) {
            String nameB = getHeaderName(hb);
            if (nameB.isEmpty()) continue;
            if (findHeader(hA, nameB) == null) {
                report.headersOnlyInB.add(hb);
            }
        }

        // Simple line diff on response bodies
        String bodyA = a.getResponseBodyAsString();
        String bodyB = b.getResponseBodyAsString();
        List<String> linesA = Arrays.asList(bodyA.split("\\r?\\n"));
        List<String> linesB = Arrays.asList(bodyB.split("\\r?\\n"));

        int maxLines = Math.max(linesA.size(), linesB.size());
        for (int i = 0; i < maxLines; i++) {
            String lineA = i < linesA.size() ? linesA.get(i) : null;
            String lineB = i < linesB.size() ? linesB.get(i) : null;

            if (lineA != null && lineB != null) {
                if (!lineA.equals(lineB)) {
                    report.bodyDiffLines.add(String.format("Line %d:\n  [-] %s\n  [+] %s", i + 1, lineA, lineB));
                }
            } else if (lineA != null) {
                report.bodyDiffLines.add(String.format("Line %d:\n  [-] %s", i + 1, lineA));
            } else {
                report.bodyDiffLines.add(String.format("Line %d:\n  [+] %s", i + 1, lineB));
            }
        }

        return report;
    }

    private static String getHeaderName(String headerLine) {
        int idx = headerLine.indexOf(':');
        if (idx > 0) {
            return headerLine.substring(0, idx).trim().toLowerCase();
        }
        return "";
    }

    private static String findHeader(List<String> headers, String name) {
        for (String h : headers) {
            if (getHeaderName(h).equalsIgnoreCase(name)) {
                return h;
            }
        }
        return null;
    }
}
