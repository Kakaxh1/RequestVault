/**
 * RequestVault for Caido - Automated Test Suite
 * Verifies replay code generators, redaction rules, and export formats.
 *
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

const { ReplayCodeGenerator } = require("../dist/script.js");

// In case script.js exports ESM, let's run test via import()
async function runTests() {
  console.log("=================================================");
  console.log(" Running RequestVault for Caido Unit Tests");
  console.log("=================================================");

  const module = await import("../dist/script.js");

  let passed = 0;
  let failed = 0;

  function assertTrue(testName, condition) {
    if (condition) {
      console.log(` [PASS] ${testName}`);
      passed++;
    } else {
      console.error(` [FAIL] ${testName}`);
      failed++;
    }
  }

  const sampleRecord = {
    recordId: "rec-1",
    sequenceNumber: 1,
    timestamp: Date.now(),
    durationMs: 45,
    method: "POST",
    host: "api.example.com",
    port: 443,
    isTls: true,
    path: "/api/v1/auth/login",
    query: "",
    url: "https://api.example.com/api/v1/auth/login",
    requestHeaders: [
      "Host: api.example.com",
      "User-Agent: Caido/1.0",
      "Authorization: Bearer secret_token_123",
      "Content-Type: application/json"
    ],
    requestBody: '{"username":"admin\'s_test","password":"secret"}',
    statusCode: 200,
    statusReason: "OK",
    responseHeaders: [
      "Content-Type: application/json",
      "Set-Cookie: session=xyz123; HttpOnly"
    ],
    responseBody: '{"status":"ok","token":"jwt_abc"}',
    contentType: "application/json",
    requestSize: 120,
    responseSize: 85,
    rawRequest: "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    rawResponse: "HTTP/1.1 200 OK\r\n\r\n",
    requestHash: "hash1",
    responseHash: "hash2",
    sourceTool: "Caido",
    inScope: true
  };

  const sampleRecord2 = {
    ...sampleRecord,
    recordId: "rec-2",
    sequenceNumber: 2,
    method: "GET",
    path: "/api/v1/profile",
    url: "https://api.example.com/api/v1/profile",
    requestBody: ""
  };

  // 1. Test cURL
  const curl = module.ReplayCodeGenerator.toCurl(sampleRecord);
  assertTrue("cURL contains -X POST", curl.includes("-X POST"));
  assertTrue("cURL contains URL", curl.includes("https://api.example.com/api/v1/auth/login"));
  assertTrue("cURL contains escaped single quote", curl.includes("'\\''"));
  assertTrue("cURL contains -k SSL bypass", curl.includes("-k"));

  const curlMulti = module.ReplayCodeGenerator.toCurlMulti([sampleRecord, sampleRecord2]);
  assertTrue("cURL multi contains shebang", curlMulti.startsWith("#!/usr/bin/env bash"));
  assertTrue("cURL multi contains Step 1", curlMulti.includes("Step 1/2"));
  assertTrue("cURL multi contains Step 2", curlMulti.includes("Step 2/2"));

  // 2. Test Python Requests
  const py = module.ReplayCodeGenerator.toPython(sampleRecord);
  assertTrue("Python imports requests", py.includes("import requests"));
  assertTrue("Python suppresses insecure warnings", py.includes("urllib3.disable_warnings"));
  assertTrue("Python sets verify=False", py.includes("verify=False"));

  const pyMulti = module.ReplayCodeGenerator.toPythonMulti([sampleRecord, sampleRecord2]);
  assertTrue("Python multi uses requests.Session()", pyMulti.includes("requests.Session()"));
  assertTrue("Python multi has step 1 request", pyMulti.includes("r1 = session.request"));
  assertTrue("Python multi has step 2 request", pyMulti.includes("r2 = session.request"));

  // 3. Test Fetch API
  const fetchCode = module.ReplayCodeGenerator.toFetch(sampleRecord);
  assertTrue("Fetch calls fetch(url, options)", fetchCode.includes("fetch(url, options)"));
  assertTrue("Fetch defines method POST", fetchCode.includes('method: "POST"'));

  const fetchMulti = module.ReplayCodeGenerator.toFetchMulti([sampleRecord, sampleRecord2]);
  assertTrue("Fetch multi defines async function", fetchMulti.includes("async function replayFlow"));
  assertTrue("Fetch multi awaits fetch", fetchMulti.includes("await fetch"));

  // 4. Test PowerShell
  const ps = module.ReplayCodeGenerator.toPowerShell(sampleRecord);
  assertTrue("PowerShell defines $headers", ps.includes("$headers = @{"));
  assertTrue("PowerShell calls Invoke-RestMethod", ps.includes("Invoke-RestMethod"));
  assertTrue("PowerShell has -SkipCertificateCheck", ps.includes("-SkipCertificateCheck"));

  // 5. Test Raw HTTP
  const raw = module.ReplayCodeGenerator.toRawHttp(sampleRecord);
  assertTrue("Raw HTTP contains request line", raw.includes("POST /api/v1/auth/login HTTP/1.1"));

  // 6. Test Redactor
  const redacted = module.Redactor.redactRecord(sampleRecord);
  assertTrue("Redactor masks Bearer token", redacted.requestHeaders.some(h => h.includes("Bearer <REDACTED>")));
  assertTrue("Redactor masks body password", redacted.requestBody.includes('"password":"<REDACTED>"'));

  // 7. Test Exporters
  const html = module.Exporters.generateHtml([sampleRecord], { format: "HTML", redactSecrets: true, includeManifest: false, separateFiles: false });
  assertTrue("HTML export contains title", html.includes("RequestVault Evidence Report"));
  assertTrue("HTML export contains footer link", html.includes("bhavymorvadiya.netlify.app"));

  const md = module.Exporters.generateMarkdown([sampleRecord], { format: "MARKDOWN", redactSecrets: true, includeManifest: false, separateFiles: false });
  assertTrue("Markdown export contains summary table", md.includes("## Summary of Captured Endpoints"));
  assertTrue("Markdown export contains code block", md.includes("```http"));

  const csv = module.Exporters.generateCsv([sampleRecord]);
  assertTrue("CSV export contains header", csv.includes("SequenceNumber,Method,Host"));

  console.log("=================================================");
  console.log(` Tests Summary: ${passed} Passed, ${failed} Failed`);
  console.log("=================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});

