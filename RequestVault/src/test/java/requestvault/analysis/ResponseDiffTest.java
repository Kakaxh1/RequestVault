package requestvault.analysis;

import requestvault.analysis.ResponseDiff.*;
import requestvault.model.TrafficRecord;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Comprehensive Unit Test Suite for ResponseDiff.
 * Verifies status diffs, header modifications, body line alignment,
 * JSONPath field parsing, binary safety, missing response handling,
 * and security-relevant observation signals.
 */
public class ResponseDiffTest {

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println(" Running RequestVault ResponseDiff Unit Tests");
        System.out.println("=================================================");

        testStatusMismatchAndAccessControlSignal();
        testHeaderDifferencesAndSecurityHeaders();
        testBodyLineDiffAndInlineDiff();
        testJsonPathFieldDifferences();
        testMalformedJsonFallback();
        testBinaryContentSafety();
        testMissingResponseHandling();
        testIdenticalResponses();

        System.out.println("=================================================");
        System.out.println(String.format(" Tests Summary: %d Passed, %d Failed", testsPassed, testsFailed));
        System.out.println("=================================================");

        if (testsFailed > 0) {
            System.exit(1);
        }
    }

    private static void assertTrue(String testName, boolean condition) {
        if (condition) {
            System.out.println(" [PASS] " + testName);
            testsPassed++;
        } else {
            System.err.println(" [FAIL] " + testName);
            testsFailed++;
        }
    }

    private static void assertEquals(String testName, Object expected, Object actual) {
        if ((expected == null && actual == null) || (expected != null && expected.equals(actual))) {
            System.out.println(" [PASS] " + testName);
            testsPassed++;
        } else {
            System.err.println(String.format(" [FAIL] %s - Expected: <%s>, Actual: <%s>", testName, expected, actual));
            testsFailed++;
        }
    }

    private static TrafficRecord createMockRecord(String id, int status, String statusReason, List<String> headers, String bodyStr, String contentType) {
        StringBuilder raw = new StringBuilder();
        raw.append("HTTP/1.1 ").append(status).append(" ").append(statusReason).append("\r\n");
        if (headers != null) {
            for (String h : headers) {
                raw.append(h).append("\r\n");
            }
        }
        raw.append("\r\n");
        int offset = raw.length();
        if (bodyStr != null) {
            raw.append(bodyStr);
        }
        byte[] respBytes = raw.toString().getBytes(StandardCharsets.UTF_8);

        return new TrafficRecord(
                id, "eng-1", new byte[10], respBytes, "https", "target.example", 443,
                "GET", "/api/profile", "https://target.example/api/profile",
                Arrays.asList("Host: target.example"), 0,
                status, statusReason, headers, offset,
                contentType != null ? contentType : "application/json",
                System.currentTimeMillis(), System.currentTimeMillis() + 50, 50,
                "Proxy", true
        );
    }

    private static void testStatusMismatchAndAccessControlSignal() {
        TrafficRecord a = createMockRecord("rec-1", 200, "OK", Arrays.asList("Content-Type: application/json"), "{\"status\":\"ok\"}", "application/json");
        TrafficRecord b = createMockRecord("rec-2", 403, "Forbidden", Arrays.asList("Content-Type: application/json"), "{\"error\":\"denied\"}", "application/json");

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("Status match should be false", !report.statusMatch);
        assertEquals("Status A should be 200", 200, report.statusA);
        assertEquals("Status B should be 403", 403, report.statusB);

        boolean foundAccessControlObs = false;
        for (SecurityObservation obs : report.securityObservations) {
            if ("Access Control".equals(obs.getCategory())) {
                foundAccessControlObs = true;
                break;
            }
        }
        assertTrue("Should detect Access Control status transition signal", foundAccessControlObs);
    }

    private static void testHeaderDifferencesAndSecurityHeaders() {
        List<String> headersA = Arrays.asList(
                "Content-Type: application/json",
                "X-Frame-Options: DENY",
                "Authorization: Bearer tokenA"
        );
        List<String> headersB = Arrays.asList(
                "Content-Type: application/json",
                "Set-Cookie: session=xyz123; HttpOnly; Secure",
                "Authorization: Bearer tokenB"
        );

        TrafficRecord a = createMockRecord("rec-3", 200, "OK", headersA, "{}", "application/json");
        TrafficRecord b = createMockRecord("rec-4", 200, "OK", headersB, "{}", "application/json");

        DiffReport report = ResponseDiff.compare(a, b);

        boolean foundRemovedHeader = false;
        boolean foundAddedCookie = false;
        boolean foundModifiedAuth = false;

        for (HeaderDiff h : report.headerDiffs) {
            if ("X-Frame-Options".equalsIgnoreCase(h.getName()) && h.getType() == DiffType.REMOVED) {
                foundRemovedHeader = true;
                assertTrue("X-Frame-Options should be marked security relevant", h.isSecurityRelevant());
            }
            if ("Set-Cookie".equalsIgnoreCase(h.getName()) && h.getType() == DiffType.ADDED) {
                foundAddedCookie = true;
                assertTrue("Set-Cookie should be marked security relevant", h.isSecurityRelevant());
            }
            if ("Authorization".equalsIgnoreCase(h.getName()) && h.getType() == DiffType.MODIFIED) {
                foundModifiedAuth = true;
            }
        }

        assertTrue("Header removed from A should be detected", foundRemovedHeader);
        assertTrue("Header added in B (Set-Cookie) should be detected", foundAddedCookie);
        assertTrue("Header modified should be detected", foundModifiedAuth);
    }

    private static void testBodyLineDiffAndInlineDiff() {
        String bodyA = "line 1\nline 2 unchanged\nuser: tester\nline 4";
        String bodyB = "line 1\nline 2 unchanged\nuser: administrator\nline 4 added";

        TrafficRecord a = createMockRecord("rec-5", 200, "OK", null, bodyA, "text/plain");
        TrafficRecord b = createMockRecord("rec-6", 200, "OK", null, bodyB, "text/plain");

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("Total diff rows should be > 0", report.totalDiffRows > 0);
        assertTrue("Unified diff lines should be present", !report.unifiedDiffLines.isEmpty());

        boolean foundModifiedUser = false;
        for (DiffRow r : report.bodyDiffRows) {
            if (r.getType() == DiffType.MODIFIED && r.getTextA().contains("user:") && r.getTextB().contains("user:")) {
                foundModifiedUser = true;
                assertTrue("Inline diff should detect exact token change", r.getInlineDiff() != null && r.getInlineDiff().contains("tester"));
            }
        }
        assertTrue("Modified user line should be detected with inline diff", foundModifiedUser);
    }

    private static void testJsonPathFieldDifferences() {
        String jsonA = "{\n  \"id\": 101,\n  \"user\": {\n    \"role\": \"user\",\n    \"name\": \"Alice\"\n  },\n  \"tempToken\": \"secret123\"\n}";
        String jsonB = "{\n  \"id\": 101,\n  \"user\": {\n    \"role\": \"admin\",\n    \"name\": \"Alice\"\n  },\n  \"permissions\": [\"read\", \"write\"]\n}";

        TrafficRecord a = createMockRecord("rec-7", 200, "OK", null, jsonA, "application/json");
        TrafficRecord b = createMockRecord("rec-8", 200, "OK", null, jsonB, "application/json");

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("isJsonA should be true", report.isJsonA);
        assertTrue("isJsonB should be true", report.isJsonB);
        assertTrue("jsonDiffs should have elements", !report.jsonDiffs.isEmpty());

        boolean foundRoleMod = false;
        boolean foundTokenRemoved = false;
        boolean foundPermissionsAdded = false;

        for (JsonFieldDiff jd : report.jsonDiffs) {
            if ("$.user.role".equals(jd.getPath())) {
                foundRoleMod = true;
                assertEquals("Role diff type should be MODIFIED", DiffType.MODIFIED, jd.getType());
                assertTrue("Role should be flagged as security relevant", jd.isSecurityRelevant());
            }
            if ("$.tempToken".equals(jd.getPath())) {
                foundTokenRemoved = true;
                assertEquals("tempToken diff type should be REMOVED", DiffType.REMOVED, jd.getType());
            }
            if (jd.getPath().startsWith("$.permissions")) {
                foundPermissionsAdded = true;
            }
        }

        assertTrue("JSONPath $.user.role modification should be found", foundRoleMod);
        assertTrue("JSONPath $.tempToken removal should be found", foundTokenRemoved);
        assertTrue("JSONPath $.permissions addition should be found", foundPermissionsAdded);
    }

    private static void testMalformedJsonFallback() {
        String malformedJsonA = "{ \"id\": 101, unclosed string ";
        String malformedJsonB = "{ \"id\": 102, unclosed string ";

        TrafficRecord a = createMockRecord("rec-9", 200, "OK", null, malformedJsonA, "application/json");
        TrafficRecord b = createMockRecord("rec-10", 200, "OK", null, malformedJsonB, "application/json");

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("isJsonA should be false for malformed JSON", !report.isJsonA);
        assertTrue("jsonDiffs should be empty without crashing", report.jsonDiffs.isEmpty());
        assertTrue("Line diffing should still execute", !report.bodyDiffRows.isEmpty());
    }

    private static void testBinaryContentSafety() {
        byte[] binaryBytes = new byte[]{0x00, 0x01, 0x02, (byte)0xFF, 0x00, 0x05};
        TrafficRecord a = new TrafficRecord(
                "rec-bin-1", "eng-1", new byte[10], binaryBytes, "https", "target.example", 443,
                "GET", "/image.png", "https://target.example/image.png",
                null, 0, 200, "OK", null, 0,
                "image/png", System.currentTimeMillis(), System.currentTimeMillis() + 10, 10, "Proxy", true
        );
        TrafficRecord b = new TrafficRecord(
                "rec-bin-2", "eng-1", new byte[10], new byte[]{0x00, 0x01, 0x02, (byte)0xFF}, "https", "target.example", 443,
                "GET", "/image.png", "https://target.example/image.png",
                null, 0, 200, "OK", null, 0,
                "image/png", System.currentTimeMillis(), System.currentTimeMillis() + 10, 10, "Proxy", true
        );

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("isBinaryA should be true", report.isBinaryA);
        assertTrue("isBinaryB should be true", report.isBinaryB);
        assertTrue("Hash A should not be empty", report.hashA != null && !report.hashA.isEmpty());
        assertTrue("Body diff row should describe binary content", report.bodyDiffRows.get(0).getTextA().contains("Binary Content"));
    }

    private static void testMissingResponseHandling() {
        TrafficRecord a = createMockRecord("rec-11", 200, "OK", null, "Hello", "text/plain");
        TrafficRecord b = new TrafficRecord(
                "rec-12", "eng-1", new byte[10], null, "https", "target.example", 443,
                "GET", "/api/timeout", "https://target.example/api/timeout",
                null, 0, 0, "", null, 0,
                "", System.currentTimeMillis(), 0, 0, "Proxy", true
        );

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("hasResponseA should be true", report.hasResponseA);
        assertTrue("hasResponseB should be false", !report.hasResponseB);
        assertTrue("statusMatch should be false", !report.statusMatch);
        assertTrue("Should handle missing response without exception", !report.bodyDiffRows.isEmpty());
    }

    private static void testIdenticalResponses() {
        String body = "{\n  \"status\": \"success\"\n}";
        List<String> headers = Arrays.asList("Content-Type: application/json", "Cache-Control: no-cache");

        TrafficRecord a = createMockRecord("rec-13", 200, "OK", headers, body, "application/json");
        TrafficRecord b = createMockRecord("rec-14", 200, "OK", headers, body, "application/json");

        DiffReport report = ResponseDiff.compare(a, b);

        assertTrue("statusMatch should be true", report.statusMatch);
        assertEquals("sizeDiff should be 0", 0, report.sizeDiff);
        assertEquals("totalDiffRows should be 0", 0, report.totalDiffRows);
        assertTrue("jsonDiffs should be empty for identical JSON", report.jsonDiffs.isEmpty());
    }
}
