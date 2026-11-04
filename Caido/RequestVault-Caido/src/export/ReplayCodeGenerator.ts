/**
 * RequestVault for Caido - Multi-Language Exploit and Replay Script Generator
 * Generates copy-pasteable replay scripts in:
 * - cURL (bash / terminal command)
 * - Python (requests library with session & SSL bypass)
 * - JavaScript (Fetch API for DevTools console & Node.js)
 * - PowerShell (Invoke-RestMethod with certificate bypass)
 * - Raw HTTP (RFC 7230 wire format)
 *
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { TrafficRecord } from "../types";

export class ReplayCodeGenerator {

  // -------------------------------------------------------------
  // 1. cURL Generator
  // -------------------------------------------------------------
  public static toCurl(record: TrafficRecord): string {
    if (!record) return "";
    const method = (record.method || "GET").toUpperCase();
    const url = record.url || "";
    const parts: string[] = [];

    parts.push(`curl -i -s -k -X ${method} "${this.escapeDoubleQuotes(url)}"`);

    if (record.requestHeaders && record.requestHeaders.length > 0) {
      for (const h of record.requestHeaders) {
        if (!h || !h.trim()) continue;
        parts.push(`  -H "${this.escapeDoubleQuotes(h)}"`);
      }
    }

    const body = record.requestBody;
    if (body) {
      const escapedBody = body.replace(/'/g, "'\\''");
      parts.push(`  --data-raw '${escapedBody}'`);
    }

    return parts.join(" \\\n");
  }

  public static toCurlMulti(records: TrafficRecord[]): string {
    if (!records || records.length === 0) return "";
    if (records.length === 1) return this.toCurl(records[0]);

    const lines: string[] = [
      "#!/usr/bin/env bash",
      "# RequestVault Generated Multi-Step cURL Replay Script",
      ""
    ];

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      lines.push(`# --- Step ${i + 1}/${records.length}: ${r.method} ${r.path} (#${r.sequenceNumber}) ---`);
      lines.push(this.toCurl(r));
      lines.push("");
    }

    return lines.join("\n").trim();
  }

  // -------------------------------------------------------------
  // 2. Python Requests Generator
  // -------------------------------------------------------------
  public static toPython(record: TrafficRecord): string {
    if (!record) return "";
    const lines: string[] = [
      "import requests",
      "import urllib3",
      "",
      "# Suppress self-signed certificate warnings for penetration testing",
      "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)",
      "",
      `url = "${this.escapeDoubleQuotes(record.url)}"`,
      "",
      "headers = {"
    ];

    if (record.requestHeaders) {
      for (const h of record.requestHeaders) {
        if (!h || !h.trim()) continue;
        const colon = h.indexOf(":");
        if (colon > 0) {
          const k = h.substring(0, colon).trim();
          const v = h.substring(colon + 1).trim();
          lines.push(`    "${this.escapeDoubleQuotes(k)}": "${this.escapeDoubleQuotes(v)}",`);
        }
      }
    }
    lines.push("}");
    lines.push("");

    const body = record.requestBody;
    if (body) {
      const escaped = body.replace(/"""/g, '\\"\\"\\"');
      lines.push(`payload = """${escaped}"""`);
    } else {
      lines.push("payload = None");
    }
    lines.push("");

    const method = (record.method || "GET").toUpperCase();
    lines.push(`response = requests.request(`);
    lines.push(`    method="${method}",`);
    lines.push(`    url=url,`);
    lines.push(`    headers=headers,`);
    if (body) {
      lines.push(`    data=payload.encode("utf-8"),`);
    }
    lines.push(`    verify=False,`);
    lines.push(`    allow_redirects=False`);
    lines.push(`)`);
    lines.push("");
    lines.push(`print(f"Status: {response.status_code}")`);
    lines.push(`print(f"Headers: {dict(response.headers)}")`);
    lines.push(`print(response.text[:1000])`);

    return lines.join("\n");
  }

  public static toPythonMulti(records: TrafficRecord[]): string {
    if (!records || records.length === 0) return "";
    if (records.length === 1) return this.toPython(records[0]);

    const lines: string[] = [
      "import requests",
      "import urllib3",
      "",
      "# Suppress self-signed certificate warnings for penetration testing",
      "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)",
      "",
      "# Initialize session to preserve cookies and state across multi-step flow",
      "session = requests.Session()",
      "session.verify = False",
      ""
    ];

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      const stepNum = i + 1;
      lines.push(`# --- Step ${stepNum}/${records.length}: ${r.method} ${r.path} (#${r.sequenceNumber}) ---`);
      lines.push(`url_${stepNum} = "${this.escapeDoubleQuotes(r.url)}"`);
      lines.push(`headers_${stepNum} = {`);
      if (r.requestHeaders) {
        for (const h of r.requestHeaders) {
          if (!h || !h.trim()) continue;
          const colon = h.indexOf(":");
          if (colon > 0) {
            const k = h.substring(0, colon).trim();
            const v = h.substring(colon + 1).trim();
            lines.push(`    "${this.escapeDoubleQuotes(k)}": "${this.escapeDoubleQuotes(v)}",`);
          }
        }
      }
      lines.push("}");

      if (r.requestBody) {
        const escaped = r.requestBody.replace(/"""/g, '\\"\\"\\"');
        lines.push(`payload_${stepNum} = """${escaped}"""`);
      } else {
        lines.push(`payload_${stepNum} = None`);
      }

      lines.push(`r${stepNum} = session.request(`);
      lines.push(`    method="${(r.method || "GET").toUpperCase()}",`);
      lines.push(`    url=url_${stepNum},`);
      lines.push(`    headers=headers_${stepNum},`);
      if (r.requestBody) {
        lines.push(`    data=payload_${stepNum}.encode("utf-8"),`);
      }
      lines.push(`    allow_redirects=False`);
      lines.push(`)`);
      lines.push(`print(f"Step ${stepNum} [${r.method} ${r.path}]: Status {r${stepNum}.status_code}")`);
      lines.push("");
    }

    return lines.join("\n").trim();
  }

  // -------------------------------------------------------------
  // 3. JavaScript Fetch Generator
  // -------------------------------------------------------------
  public static toFetch(record: TrafficRecord): string {
    if (!record) return "";
    const lines: string[] = [
      `const url = "${this.escapeDoubleQuotes(record.url)}";`,
      "",
      `const headers = {`
    ];

    if (record.requestHeaders) {
      for (const h of record.requestHeaders) {
        if (!h || !h.trim()) continue;
        const colon = h.indexOf(":");
        if (colon > 0) {
          const k = h.substring(0, colon).trim();
          const v = h.substring(colon + 1).trim();
          lines.push(`  "${this.escapeDoubleQuotes(k)}": "${this.escapeDoubleQuotes(v)}",`);
        }
      }
    }
    lines.push(`};`);
    lines.push("");

    const method = (record.method || "GET").toUpperCase();
    lines.push(`const options = {`);
    lines.push(`  method: "${method}",`);
    lines.push(`  headers: headers,`);
    if (record.requestBody) {
      lines.push(`  body: ${JSON.stringify(record.requestBody)},`);
    }
    lines.push(`  redirect: "manual"`);
    lines.push(`};`);
    lines.push("");
    lines.push(`fetch(url, options)`);
    lines.push(`  .then(async (response) => {`);
    lines.push(`    console.log("Status:", response.status, response.statusText);`);
    lines.push(`    const body = await response.text();`);
    lines.push(`    console.log("Response Body (first 500 chars):", body.slice(0, 500));`);
    lines.push(`  })`);
    lines.push(`  .catch((err) => console.error("Request failed:", err));`);

    return lines.join("\n");
  }

  public static toFetchMulti(records: TrafficRecord[]): string {
    if (!records || records.length === 0) return "";
    if (records.length === 1) return this.toFetch(records[0]);

    const lines: string[] = [
      `async function replayFlow() {`,
      `  console.log("Starting RequestVault replay flow (${records.length} steps)...");`,
      ""
    ];

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      const step = i + 1;
      lines.push(`  // --- Step ${step}/${records.length}: ${r.method} ${r.path} (#${r.sequenceNumber}) ---`);
      lines.push(`  {`);
      lines.push(`    const res = await fetch("${this.escapeDoubleQuotes(r.url)}", {`);
      lines.push(`      method: "${(r.method || "GET").toUpperCase()}",`);
      lines.push(`      headers: {`);
      if (r.requestHeaders) {
        for (const h of r.requestHeaders) {
          if (!h || !h.trim()) continue;
          const colon = h.indexOf(":");
          if (colon > 0) {
            const k = h.substring(0, colon).trim();
            const v = h.substring(colon + 1).trim();
            lines.push(`        "${this.escapeDoubleQuotes(k)}": "${this.escapeDoubleQuotes(v)}",`);
          }
        }
      }
      lines.push(`      },`);
      if (r.requestBody) {
        lines.push(`      body: ${JSON.stringify(r.requestBody)},`);
      }
      lines.push(`      redirect: "manual"`);
      lines.push(`    });`);
      lines.push(`    console.log("Step ${step} Status:", res.status);`);
      lines.push(`  }`);
      lines.push("");
    }

    lines.push(`  console.log("Replay flow completed successfully.");`);
    lines.push(`}`);
    lines.push(`replayFlow();`);

    return lines.join("\n").trim();
  }

  // -------------------------------------------------------------
  // 4. PowerShell Generator
  // -------------------------------------------------------------
  public static toPowerShell(record: TrafficRecord): string {
    if (!record) return "";
    const lines: string[] = [
      `$headers = @{`
    ];

    if (record.requestHeaders) {
      for (const h of record.requestHeaders) {
        if (!h || !h.trim()) continue;
        const colon = h.indexOf(":");
        if (colon > 0) {
          const k = h.substring(0, colon).trim();
          const v = h.substring(colon + 1).trim();
          lines.push(`    "${this.escapeDoubleQuotes(k)}" = "${this.escapeDoubleQuotes(v)}"`);
        }
      }
    }
    lines.push(`}`);
    lines.push("");

    const body = record.requestBody;
    if (body) {
      lines.push(`$body = @"`);
      lines.push(body);
      lines.push(`"@`);
      lines.push("");
    }

    const method = (record.method || "GET").toUpperCase();
    lines.push(`$response = Invoke-RestMethod -Method ${method} \``);
    lines.push(`    -Uri "${this.escapeDoubleQuotes(record.url)}" \``);
    lines.push(`    -Headers $headers \``);
    if (body) {
      lines.push(`    -Body $body \``);
    }
    lines.push(`    -SkipCertificateCheck`);
    lines.push("");
    lines.push(`Write-Output "Response: $response"`);

    return lines.join("\n");
  }

  public static toPowerShellMulti(records: TrafficRecord[]): string {
    if (!records || records.length === 0) return "";
    if (records.length === 1) return this.toPowerShell(records[0]);

    const lines: string[] = [
      "# RequestVault Multi-Step PowerShell Replay Script",
      ""
    ];

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      const step = i + 1;
      lines.push(`# --- Step ${step}/${records.length}: ${r.method} ${r.path} (#${r.sequenceNumber}) ---`);
      lines.push(`$headers_${step} = @{`);
      if (r.requestHeaders) {
        for (const h of r.requestHeaders) {
          if (!h || !h.trim()) continue;
          const colon = h.indexOf(":");
          if (colon > 0) {
            const k = h.substring(0, colon).trim();
            const v = h.substring(colon + 1).trim();
            lines.push(`    "${this.escapeDoubleQuotes(k)}" = "${this.escapeDoubleQuotes(v)}"`);
          }
        }
      }
      lines.push(`}`);

      if (r.requestBody) {
        lines.push(`$body_${step} = @"`);
        lines.push(r.requestBody);
        lines.push(`"@`);
      }

      lines.push(`$res_${step} = Invoke-RestMethod -Method ${(r.method || "GET").toUpperCase()} \``);
      lines.push(`    -Uri "${this.escapeDoubleQuotes(r.url)}" \``);
      lines.push(`    -Headers $headers_${step} \``);
      if (r.requestBody) {
        lines.push(`    -Body $body_${step} \``);
      }
      lines.push(`    -SkipCertificateCheck`);
      lines.push(`Write-Output "Step ${step} Status: Done"`);
      lines.push("");
    }

    return lines.join("\n").trim();
  }

  // -------------------------------------------------------------
  // 5. Raw HTTP (RFC 7230) Generator
  // -------------------------------------------------------------
  public static toRawHttp(record: TrafficRecord): string {
    if (!record) return "";
    if (record.rawRequest) return record.rawRequest;

    const method = (record.method || "GET").toUpperCase();
    const path = record.path || "/";
    const lines: string[] = [`${method} ${path} HTTP/1.1`];

    let hasHost = false;
    if (record.requestHeaders) {
      for (const h of record.requestHeaders) {
        if (!h || !h.trim()) continue;
        if (h.toLowerCase().startsWith("host:")) hasHost = true;
        lines.push(h);
      }
    }
    if (!hasHost && record.host) {
      const hostVal = record.port === 80 || record.port === 443 ? record.host : `${record.host}:${record.port}`;
      lines.splice(1, 0, `Host: ${hostVal}`);
    }

    lines.push("");
    if (record.requestBody) {
      lines.push(record.requestBody);
    }
    return lines.join("\r\n");
  }

  public static toRawHttpMulti(records: TrafficRecord[]): string {
    if (!records || records.length === 0) return "";
    if (records.length === 1) return this.toRawHttp(records[0]);

    const blocks: string[] = [];
    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      blocks.push(
        `# ================================================================\n` +
        `# TRANSACTION #${r.sequenceNumber} [Step ${i + 1}/${records.length}]: ${r.method} ${r.path}\n` +
        `# Host: ${r.host}:${r.port} (${r.isTls ? "HTTPS" : "HTTP"})\n` +
        `# ================================================================\n` +
        this.toRawHttp(r)
      );
    }
    return blocks.join("\n\n");
  }

  private static escapeDoubleQuotes(s: string): string {
    if (!s) return "";
    return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }
}

