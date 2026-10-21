package requestvault.analysis;

import requestvault.analysis.TrafficFilter.*;
import requestvault.export.ExportPreset;
import requestvault.export.PresetManager;
import requestvault.model.TrafficRecord;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Unit Test Suite for RequestVault Smart Filters, Advanced Traffic Search, and Export Presets.
 */
public class TrafficFilterAndPresetTest {

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println(" Running RequestVault Filter & Preset Unit Tests");
        System.out.println("=================================================");

        testBuiltInPresets();
        testCustomPresetSaveAndDelete();
        testSmartFilterStatusCodeCategories();
        testSmartFilterCustomStatusRanges();
        testSmartFilterMimeCategories();
        testSmartFilterAuthEndpoints();
        testSmartFilterTimeRanges();
        testSmartFilterSubdomainsAndHosts();
        testAdvancedTrafficSearchScopes();
        testAdvancedTrafficSearchRegexAndCaseSensitivity();
        testAdvancedTrafficSearchInvertMatch();

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

    private static TrafficRecord createRecord(int seq, String method, String host, String path, int status, String mime, String reqBody, String respBody, List<String> reqHeaders, List<String> respHeaders) {
        return createRecord(seq, method, host, path, status, mime, reqBody, respBody, reqHeaders, respHeaders, System.currentTimeMillis());
    }

    private static TrafficRecord createRecord(int seq, String method, String host, String path, int status, String mime, String reqBody, String respBody, List<String> reqHeaders, List<String> respHeaders, long reqTime) {
        StringBuilder reqRaw = new StringBuilder();
        reqRaw.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
        reqRaw.append("Host: ").append(host).append("\r\n");
        if (reqHeaders != null) {
            for (String h : reqHeaders) reqRaw.append(h).append("\r\n");
        }
        reqRaw.append("\r\n");
        int reqOffset = reqRaw.length();
        if (reqBody != null) reqRaw.append(reqBody);
        byte[] reqBytes = reqRaw.toString().getBytes(StandardCharsets.UTF_8);

        StringBuilder respRaw = new StringBuilder();
        respRaw.append("HTTP/1.1 ").append(status).append(" OK\r\n");
        respRaw.append("Content-Type: ").append(mime != null ? mime : "application/json").append("\r\n");
        if (respHeaders != null) {
            for (String h : respHeaders) respRaw.append(h).append("\r\n");
        }
        respRaw.append("\r\n");
        int respOffset = respRaw.length();
        if (respBody != null) respRaw.append(respBody);
        byte[] respBytes = respRaw.toString().getBytes(StandardCharsets.UTF_8);

        List<String> finalReqHeaders = reqHeaders != null ? new ArrayList<>(reqHeaders) : new ArrayList<>(Collections.singletonList("Host: " + host));
        List<String> finalRespHeaders = respHeaders != null ? new ArrayList<>(respHeaders) : new ArrayList<>(Collections.singletonList("Content-Type: " + mime));

        TrafficRecord r = new TrafficRecord(
                "rec-" + seq,
                "ENG-001",
                reqBytes,
                respBytes,
                "https",
                host,
                443,
                method,
                path,
                "https://" + host + path,
                finalReqHeaders,
                reqOffset,
                status,
                "OK",
                finalRespHeaders,
                respOffset,
                mime != null ? mime : "application/json",
                reqTime,
                reqTime + 45,
                45L,
                "Proxy",
                true
        );
        r.setSequenceNumber(seq);
        return r;
    }

    private static void testBuiltInPresets() {
        PresetManager manager = new PresetManager();
        List<ExportPreset> presets = manager.getAllPresets();
        assertTrue("PresetManager loads at least 6 built-in presets", presets.size() >= 6);

        boolean foundHtml = false;
        boolean foundJson = false;
        boolean foundHar = false;
        boolean foundRaw = false;
        boolean foundMd = false;
        boolean foundCsv = false;

        for (ExportPreset p : presets) {
            if (p.getFormatName().contains("HTML")) foundHtml = true;
            if (p.getFormatName().contains("JSON")) foundJson = true;
            if (p.getFormatName().contains("HAR")) foundHar = true;
            if (p.getFormatName().contains("RAW")) foundRaw = true;
            if (p.getFormatName().contains("Markdown")) foundMd = true;
            if (p.getFormatName().contains("CSV")) foundCsv = true;
        }

        assertTrue("Built-in HTML Preset present", foundHtml);
        assertTrue("Built-in JSON Preset present", foundJson);
        assertTrue("Built-in HAR Preset present", foundHar);
        assertTrue("Built-in RAW Preset present", foundRaw);
        assertTrue("Built-in Markdown Preset present", foundMd);
        assertTrue("Built-in CSV Preset present", foundCsv);
    }

    private static void testCustomPresetSaveAndDelete() {
        PresetManager manager = new PresetManager();
        String customName = "Test Custom Penetration Preset";
        ExportPreset custom = new ExportPreset(customName, "Test Description", "JSON (.json)", false, false, true, false, false);
        manager.saveCustomPreset(custom);

        ExportPreset fetched = manager.getPreset(customName);
        assertTrue("Custom preset saved and retrieved", fetched != null && fetched.getName().equals(customName));
        assertTrue("Custom preset separateFiles flag preserved", fetched != null && fetched.isSeparateFiles());

        manager.deleteCustomPreset(customName);
        ExportPreset deleted = manager.getPreset(customName);
        assertTrue("Custom preset deleted successfully", deleted == null);
    }

    private static void testSmartFilterStatusCodeCategories() {
        TrafficRecord r200 = createRecord(1, "GET", "api.example.com", "/users", 200, "application/json", null, "{}", null, null);
        TrafficRecord r302 = createRecord(2, "GET", "api.example.com", "/redirect", 302, "text/html", null, "", null, null);
        TrafficRecord r404 = createRecord(3, "GET", "api.example.com", "/notfound", 404, "application/json", null, "{}", null, null);
        TrafficRecord r500 = createRecord(4, "POST", "api.example.com", "/crash", 500, "text/plain", "{}", "err", null, null);
        List<TrafficRecord> list = Arrays.asList(r200, r302, r404, r500);

        TrafficFilter filter2xx = new TrafficFilter();
        filter2xx.setStatusCodeGroup("2xx");
        List<TrafficRecord> res2xx = filter2xx.filter(list);
        assertTrue("Filter 2xx matches only 200", res2xx.size() == 1 && res2xx.get(0).getStatusCode() == 200);

        TrafficFilter filter4xx = new TrafficFilter();
        filter4xx.setStatusCodeGroup("4xx");
        List<TrafficRecord> res4xx = filter4xx.filter(list);
        assertTrue("Filter 4xx matches only 404", res4xx.size() == 1 && res4xx.get(0).getStatusCode() == 404);

        TrafficFilter filter5xx = new TrafficFilter();
        filter5xx.setStatusCodeGroup("5xx");
        List<TrafficRecord> res5xx = filter5xx.filter(list);
        assertTrue("Filter 5xx matches only 500", res5xx.size() == 1 && res5xx.get(0).getStatusCode() == 500);
    }

    private static void testSmartFilterCustomStatusRanges() {
        TrafficRecord r200 = createRecord(1, "GET", "api.example.com", "/test", 200, "application/json", null, "", null, null);
        TrafficRecord r401 = createRecord(2, "GET", "api.example.com", "/test", 401, "application/json", null, "", null, null);
        TrafficRecord r403 = createRecord(3, "GET", "api.example.com", "/test", 403, "application/json", null, "", null, null);
        TrafficRecord r404 = createRecord(4, "GET", "api.example.com", "/test", 404, "application/json", null, "", null, null);
        TrafficRecord r502 = createRecord(5, "GET", "api.example.com", "/test", 502, "application/json", null, "", null, null);
        List<TrafficRecord> list = Arrays.asList(r200, r401, r403, r404, r502);

        TrafficFilter filter = new TrafficFilter();
        filter.setStatusCodeCustom("401-403, 5xx");
        List<TrafficRecord> matched = filter.filter(list);
        assertTrue("Filter custom status range 401-403, 5xx matches 401, 403, and 502",
                matched.size() == 3 && matched.contains(r401) && matched.contains(r403) && matched.contains(r502));
    }

    private static void testSmartFilterMimeCategories() {
        TrafficRecord rJson = createRecord(1, "GET", "api.example.com", "/data", 200, "application/json; charset=utf-8", null, "{}", null, null);
        TrafficRecord rHtml = createRecord(2, "GET", "api.example.com", "/page", 200, "text/html", null, "<html></html>", null, null);
        TrafficRecord rImg = createRecord(3, "GET", "api.example.com", "/logo.png", 200, "image/png", null, null, null, null);
        List<TrafficRecord> list = Arrays.asList(rJson, rHtml, rImg);

        TrafficFilter filterJson = new TrafficFilter();
        filterJson.setMimeCategory(MimeCategory.JSON);
        List<TrafficRecord> resJson = filterJson.filter(list);
        assertTrue("MimeCategory.JSON matches application/json", resJson.size() == 1 && resJson.get(0).getContentType().contains("json"));

        TrafficFilter filterMedia = new TrafficFilter();
        filterMedia.setMimeCategory(MimeCategory.BINARY_MEDIA);
        List<TrafficRecord> resMedia = filterMedia.filter(list);
        assertTrue("MimeCategory.BINARY_MEDIA matches image/png", resMedia.size() == 1 && resMedia.get(0).getContentType().contains("image"));
    }

    private static void testSmartFilterAuthEndpoints() {
        TrafficRecord rAuthPath = createRecord(1, "POST", "api.example.com", "/api/v1/auth/token", 200, "application/json", "{\"user\":\"admin\"}", "{\"token\":\"xyz\"}", null, null);
        TrafficRecord rAuthHeader = createRecord(2, "GET", "api.example.com", "/dashboard", 200, "text/html", null, "ok", Arrays.asList("Authorization: Bearer test_token"), null);
        TrafficRecord rNormal = createRecord(3, "GET", "api.example.com", "/products/123", 200, "application/json", null, "{}", null, null);
        List<TrafficRecord> list = Arrays.asList(rAuthPath, rAuthHeader, rNormal);

        TrafficFilter filter = new TrafficFilter();
        filter.setAuthEndpointsOnly(true);
        List<TrafficRecord> authMatched = filter.filter(list);

        assertTrue("Auth endpoints filter matches path keyword (/auth/token) and Authorization header",
                authMatched.size() == 2 && authMatched.contains(rAuthPath) && authMatched.contains(rAuthHeader) && !authMatched.contains(rNormal));
    }

    private static void testSmartFilterTimeRanges() {
        long now = System.currentTimeMillis();
        TrafficRecord rNow = createRecord(1, "GET", "api.example.com", "/recent", 200, "application/json", null, "{}", null, null, now - 60_000); // 1 min ago
        TrafficRecord rOld = createRecord(2, "GET", "api.example.com", "/old", 200, "application/json", null, "{}", null, null, now - 3_600_000 * 2); // 2 hours ago

        List<TrafficRecord> list = Arrays.asList(rNow, rOld);

        TrafficFilter filter5m = new TrafficFilter();
        filter5m.setTimeRangeMode(TimeRangeMode.LAST_5_MIN);
        List<TrafficRecord> res5m = filter5m.filter(list);
        assertTrue("TimeRange LAST_5_MIN includes 1 min ago but excludes 2 hours ago",
                res5m.size() == 1 && res5m.get(0).getUrl().contains("recent"));

        TrafficFilter filter24h = new TrafficFilter();
        filter24h.setTimeRangeMode(TimeRangeMode.LAST_24_HOURS);
        List<TrafficRecord> res24h = filter24h.filter(list);
        assertTrue("TimeRange LAST_24_HOURS includes both", res24h.size() == 2);
    }

    private static void testSmartFilterSubdomainsAndHosts() {
        TrafficRecord r1 = createRecord(1, "GET", "auth.corp.local", "/login", 200, "text/html", null, "", null, null);
        TrafficRecord r2 = createRecord(2, "GET", "api.corp.local", "/v1/data", 200, "application/json", null, "", null, null);
        TrafficRecord r3 = createRecord(3, "GET", "otherdomain.com", "/index", 200, "text/html", null, "", null, null);
        List<TrafficRecord> list = Arrays.asList(r1, r2, r3);

        TrafficFilter filterDomain = new TrafficFilter();
        Set<String> domains = new HashSet<>(Collections.singletonList("corp.local"));
        filterDomain.setEnabledDomains(domains);
        List<TrafficRecord> res = filterDomain.filter(list);
        assertTrue("Filter enabledDomains matches subdomains of corp.local and excludes otherdomain.com",
                res.size() == 2 && res.contains(r1) && res.contains(r2));
    }

    private static void testAdvancedTrafficSearchScopes() {
        TrafficRecord r = createRecord(1, "POST", "api.internal.net", "/v2/transfer?account=9876", 201, "application/json",
                "{\"amount\": 5000, \"currency\": \"USD\"}",
                "{\"transaction_id\": \"TXN-4455\", \"status\": \"SUCCESS\"}",
                Arrays.asList("X-Internal-Token: secret_token_123"),
                Arrays.asList("X-Server-Id: worker-node-09"));

        List<TrafficRecord> list = Collections.singletonList(r);

        // Search in Headers only
        TrafficFilter fHeader = new TrafficFilter();
        fHeader.setAdvancedSearch("secret_token_123", SearchScope.HEADERS, false, false, false);
        assertTrue("Search in HEADERS matches X-Internal-Token", fHeader.filter(list).size() == 1);

        // Search for header token in REQ_BODY (should fail)
        TrafficFilter fBodyOnly = new TrafficFilter();
        fBodyOnly.setAdvancedSearch("secret_token_123", SearchScope.REQ_BODY, false, false, false);
        assertTrue("Search in REQ_BODY does not find header token", fBodyOnly.filter(list).isEmpty());

        // Search in REQ_BODY
        fBodyOnly.setAdvancedSearch("5000", SearchScope.REQ_BODY, false, false, false);
        assertTrue("Search in REQ_BODY finds amount 5000", fBodyOnly.filter(list).size() == 1);

        // Search in RESP_BODY
        TrafficFilter fResp = new TrafficFilter();
        fResp.setAdvancedSearch("TXN-4455", SearchScope.RESP_BODY, false, false, false);
        assertTrue("Search in RESP_BODY finds TXN-4455", fResp.filter(list).size() == 1);

        // Search in PARAMS
        TrafficFilter fParam = new TrafficFilter();
        fParam.setAdvancedSearch("account", SearchScope.PARAMS, false, false, false);
        assertTrue("Search in PARAMS finds query parameter 'account'", fParam.filter(list).size() == 1);

        // Search in METHOD
        TrafficFilter fMethod = new TrafficFilter();
        fMethod.setAdvancedSearch("POST", SearchScope.METHOD, false, false, false);
        assertTrue("Search in METHOD finds 'POST'", fMethod.filter(list).size() == 1);
    }

    private static void testAdvancedTrafficSearchRegexAndCaseSensitivity() {
        TrafficRecord r = createRecord(1, "GET", "api.example.com", "/test", 200, "text/plain", null, "SensitiveSecretValue123", null, null);
        List<TrafficRecord> list = Collections.singletonList(r);

        // Case-sensitive mismatch
        TrafficFilter fCaseMismatch = new TrafficFilter();
        fCaseMismatch.setAdvancedSearch("sensitivesecretvalue123", SearchScope.EVERYWHERE, true, false, false);
        assertTrue("Case-sensitive search fails when case differs", fCaseMismatch.filter(list).isEmpty());

        // Case-sensitive match
        TrafficFilter fCaseMatch = new TrafficFilter();
        fCaseMatch.setAdvancedSearch("SensitiveSecretValue123", SearchScope.EVERYWHERE, true, false, false);
        assertTrue("Case-sensitive search succeeds when case matches exactly", fCaseMatch.filter(list).size() == 1);

        // Regex match
        TrafficFilter fRegex = new TrafficFilter();
        fRegex.setAdvancedSearch("SensitiveSecretValue\\d+", SearchScope.EVERYWHERE, false, true, false);
        assertTrue("Regex search matches pattern SensitiveSecretValue\\d+", fRegex.filter(list).size() == 1);
    }

    private static void testAdvancedTrafficSearchInvertMatch() {
        TrafficRecord r1 = createRecord(1, "GET", "api.example.com", "/health", 200, "text/plain", null, "healthy", null, null);
        TrafficRecord r2 = createRecord(2, "GET", "api.example.com", "/error", 500, "text/plain", null, "internal error", null, null);
        List<TrafficRecord> list = Arrays.asList(r1, r2);

        TrafficFilter fInvert = new TrafficFilter();
        fInvert.setAdvancedSearch("healthy", SearchScope.EVERYWHERE, false, false, true);
        List<TrafficRecord> res = fInvert.filter(list);
        assertTrue("Invert match returns records that do NOT contain 'healthy'",
                res.size() == 1 && res.get(0).getStatusCode() == 500);
    }
}
