package requestvault.export;

import requestvault.model.TrafficRecord;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Unit Test Suite for Multi-Language Replay Code Generator.
 * Verifies code generation for cURL, Python requests, JavaScript fetch, PowerShell, and Raw HTTP RFC 7230.
 */
public class ReplayCodeGeneratorTest {

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println(" Running RequestVault Replay Generator Unit Tests");
        System.out.println("=================================================");

        testCurlSingleRecord();
        testCurlMultipleRecords();
        testPythonSingleRecord();
        testPythonMultipleRecords();
        testFetchSingleRecord();
        testFetchMultipleRecords();
        testPowerShellSingleRecord();
        testPowerShellMultipleRecords();
        testRawHttpSingleAndMultiple();

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

    private static TrafficRecord createRecord(int seq, String method, String host, String path, List<String> reqHeaders, String reqBody) {
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

        byte[] respBytes = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        List<String> finalReqHeaders = reqHeaders != null ? new ArrayList<>(reqHeaders) : new ArrayList<>(Collections.singletonList("Host: " + host));
        List<String> finalRespHeaders = Collections.singletonList("Content-Type: application/json");

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
                200,
                "OK",
                finalRespHeaders,
                38,
                "application/json",
                System.currentTimeMillis(),
                System.currentTimeMillis() + 45,
                45L,
                "Proxy",
                true
        );
        r.setSequenceNumber(seq);
        return r;
    }

    private static void testCurlSingleRecord() {
        TrafficRecord r = createRecord(1, "POST", "api.target.com", "/v1/auth/login",
                Arrays.asList("Host: api.target.com", "Content-Type: application/json", "Authorization: Bearer secret_token_123"),
                "{\"username\":\"admin\",\"password\":\"P@ss'word123\"}");

        String curl = ReplayCodeGenerator.toCurl(r);
        assertTrue("cURL contains method -X POST", curl.contains("-X POST"));
        assertTrue("cURL contains URL", curl.contains("https://api.target.com/v1/auth/login"));
        assertTrue("cURL contains Authorization header", curl.contains("-H \"Authorization: Bearer secret_token_123\""));
        assertTrue("cURL contains escaped single quote in payload", curl.contains("'\\''"));
        assertTrue("cURL contains -k flag for insecure SSL", curl.contains("-k"));
    }

    private static void testCurlMultipleRecords() {
        TrafficRecord r1 = createRecord(1, "GET", "api.target.com", "/v1/users", null, null);
        TrafficRecord r2 = createRecord(2, "DELETE", "api.target.com", "/v1/users/42", null, null);

        String curlScript = ReplayCodeGenerator.toCurl(Arrays.asList(r1, r2));
        assertTrue("Multi-cURL starts with bash shebang", curlScript.startsWith("#!/usr/bin/env bash"));
        assertTrue("Multi-cURL contains step 1", curlScript.contains("Step 1/2"));
        assertTrue("Multi-cURL contains step 2", curlScript.contains("Step 2/2"));
        assertTrue("Multi-cURL contains -X DELETE", curlScript.contains("-X DELETE"));
    }

    private static void testPythonSingleRecord() {
        TrafficRecord r = createRecord(1, "PUT", "api.target.com", "/v1/settings",
                Arrays.asList("Content-Type: application/json", "X-Custom-Auth: key_abc"),
                "{\"theme\":\"dark\"}");

        String py = ReplayCodeGenerator.toPython(r);
        assertTrue("Python script imports requests", py.contains("import requests"));
        assertTrue("Python script disables insecure warnings", py.contains("urllib3.disable_warnings"));
        assertTrue("Python script sets url", py.contains("url = \"https://api.target.com/v1/settings\""));
        assertTrue("Python script includes headers dict", py.contains("\"X-Custom-Auth\": \"key_abc\""));
        assertTrue("Python script sets payload", py.contains("payload = \"\"\"{\"theme\":\"dark\"}\"\"\""));
        assertTrue("Python script disables SSL verification", py.contains("verify=False"));
    }

    private static void testPythonMultipleRecords() {
        TrafficRecord r1 = createRecord(1, "POST", "api.target.com", "/login", null, "user=test");
        TrafficRecord r2 = createRecord(2, "GET", "api.target.com", "/dashboard", null, null);

        String pySession = ReplayCodeGenerator.toPython(Arrays.asList(r1, r2));
        assertTrue("Multi-Python uses requests.Session()", pySession.contains("session = requests.Session()"));
        assertTrue("Multi-Python session disables verify", pySession.contains("session.verify = False"));
        assertTrue("Multi-Python calls r1 = session.request", pySession.contains("r1 = session.request"));
        assertTrue("Multi-Python calls r2 = session.request", pySession.contains("r2 = session.request"));
    }

    private static void testFetchSingleRecord() {
        TrafficRecord r = createRecord(1, "POST", "api.target.com", "/graphql",
                Arrays.asList("Content-Type: application/json"),
                "{\"query\":\"{ user { id name } }\"}");

        String fetch = ReplayCodeGenerator.toFetch(r);
        assertTrue("Fetch defines url", fetch.contains("const url = \"https://api.target.com/graphql\""));
        assertTrue("Fetch defines method POST", fetch.contains("method: \"POST\""));
        assertTrue("Fetch includes headers", fetch.contains("\"Content-Type\": \"application/json\""));
        assertTrue("Fetch includes body", fetch.contains("body:"));
        assertTrue("Fetch includes .then(async (response)", fetch.contains("fetch(url, options)"));
    }

    private static void testFetchMultipleRecords() {
        TrafficRecord r1 = createRecord(1, "GET", "api.target.com", "/api/item1", null, null);
        TrafficRecord r2 = createRecord(2, "GET", "api.target.com", "/api/item2", null, null);

        String fetchFlow = ReplayCodeGenerator.toFetch(Arrays.asList(r1, r2));
        assertTrue("Multi-Fetch defines async function replayFlow", fetchFlow.contains("async function replayFlow()"));
        assertTrue("Multi-Fetch awaits fetch calls", fetchFlow.contains("const res = await fetch("));
        assertTrue("Multi-Fetch invokes replayFlow()", fetchFlow.contains("replayFlow();"));
    }

    private static void testPowerShellSingleRecord() {
        TrafficRecord r = createRecord(1, "POST", "internal.corp", "/upload",
                Arrays.asList("X-Token: 123"), "sample payload text");

        String ps = ReplayCodeGenerator.toPowerShell(r);
        assertTrue("PowerShell defines $headers hashtable", ps.contains("$headers = @{"));
        assertTrue("PowerShell includes X-Token header", ps.contains("\"X-Token\" = \"123\""));
        assertTrue("PowerShell defines $body here-string", ps.contains("$body = @\""));
        assertTrue("PowerShell calls Invoke-RestMethod", ps.contains("Invoke-RestMethod -Uri \"https://internal.corp/upload\""));
        assertTrue("PowerShell has -SkipCertificateCheck", ps.contains("-SkipCertificateCheck"));
    }

    private static void testPowerShellMultipleRecords() {
        TrafficRecord r1 = createRecord(1, "GET", "internal.corp", "/step1", null, null);
        TrafficRecord r2 = createRecord(2, "POST", "internal.corp", "/step2", null, "data=1");

        String multiPs = ReplayCodeGenerator.toPowerShell(Arrays.asList(r1, r2));
        assertTrue("Multi-PowerShell contains step 1", multiPs.contains("Step 1:"));
        assertTrue("Multi-PowerShell contains step 2", multiPs.contains("Step 2:"));
        assertTrue("Multi-PowerShell contains multiple Invoke-RestMethod calls", multiPs.split("Invoke-RestMethod").length >= 3);
    }

    private static void testRawHttpSingleAndMultiple() {
        TrafficRecord r = createRecord(1, "POST", "example.com", "/submit",
                Arrays.asList("Host: example.com", "Content-Type: text/plain"),
                "Hello World");

        String raw = ReplayCodeGenerator.toRawHttp(r);
        assertTrue("Raw HTTP contains request line", raw.startsWith("POST /submit HTTP/1.1\r\n"));
        assertTrue("Raw HTTP contains Host header", raw.contains("Host: example.com\r\n"));
        assertTrue("Raw HTTP contains body", raw.endsWith("Hello World"));

        TrafficRecord r2 = createRecord(2, "GET", "example.com", "/status", null, null);
        String multiRaw = ReplayCodeGenerator.toRawHttp(Arrays.asList(r, r2));
        assertTrue("Multi-Raw HTTP contains Transaction delimiters", multiRaw.contains("### Transaction #1") && multiRaw.contains("### Transaction #2"));
    }
}
