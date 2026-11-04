/**
 * RequestVault for Caido - Multi-Format Evidence Exporters
 * Exports to HTML Report, Markdown Dossier, JSON, CSV, HAR 1.2, and SHA-256 Evidence Manifest
 *
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { ExportOptions, TrafficRecord } from "../types";
import { Redactor } from "./Redactor";

export class Exporters {

  public static async calculateSha256(text: string): Promise<string> {
    if (!text) return "";
    try {
      const msgBuffer = new TextEncoder().encode(text);
      const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    } catch {
      return "";
    }
  }

  // -------------------------------------------------------------
  // 1. Interactive HTML Report
  // -------------------------------------------------------------
  public static generateHtml(records: TrafficRecord[], options: ExportOptions): string {
    const targets = options.redactSecrets ? records.map(r => Redactor.redactRecord(r)) : records;
    const dateStr = new Date().toISOString().split("T")[0];

    const rowsHtml = targets.map((r, i) => {
      const statusClass = r.statusCode >= 200 && r.statusCode < 300 ? "status-2xx"
        : r.statusCode >= 300 && r.statusCode < 400 ? "status-3xx"
        : r.statusCode >= 400 && r.statusCode < 500 ? "status-4xx"
        : r.statusCode >= 500 ? "status-5xx" : "status-other";

      const reqHeaders = (r.requestHeaders || []).join("\n");
      const respHeaders = (r.responseHeaders || []).join("\n");

      return `
      <div class="record-card" id="record-${r.sequenceNumber}">
        <div class="record-header">
          <span class="badge seq-badge">#${r.sequenceNumber}</span>
          <span class="badge method-badge method-${(r.method || "GET").toLowerCase()}">${r.method}</span>
          <span class="url-text">${this.escapeHtml(r.url)}</span>
          <span class="badge status-badge ${statusClass}">${r.statusCode || "-"}</span>
          <span class="time-text">${r.durationMs}ms</span>
        </div>
        <div class="record-body">
          <div class="flow-col">
            <h4>Request Headers & Body</h4>
            <pre class="code-block"><code>${this.escapeHtml(reqHeaders)}\n\n${this.escapeHtml(r.requestBody || "")}</code></pre>
          </div>
          <div class="flow-col">
            <h4>Response Headers & Body</h4>
            <pre class="code-block"><code>${this.escapeHtml(respHeaders)}\n\n${this.escapeHtml(r.responseBody || "")}</code></pre>
          </div>
        </div>
        <div class="record-footer">
          <span>SHA-256 (Req): <code>${r.requestHash || "-"}</code></span> |
          <span>SHA-256 (Resp): <code>${r.responseHash || "-"}</code></span>
        </div>
      </div>`;
    }).join("\n");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RequestVault Evidence Report - ${dateStr}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #ff7a45;
      --link: #58a6ff;
    }
    body {
      margin: 0;
      padding: 24px;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 { margin: 0 0 8px 0; color: var(--accent); font-size: 24px; }
    .meta-bar { font-size: 13px; color: var(--text-muted); }
    .record-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .record-header {
      padding: 10px 16px;
      background: rgba(255, 255, 255, 0.02);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
    }
    .url-text {
      flex: 1;
      font-family: monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      color: #79c0ff;
    }
    .badge {
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: bold;
    }
    .seq-badge { background: #21262d; color: #8b949e; }
    .method-get { background: #1f6feb; color: white; }
    .method-post { background: #238636; color: white; }
    .method-put { background: #d29922; color: white; }
    .method-delete { background: #da3633; color: white; }
    .status-2xx { background: #238636; color: white; }
    .status-3xx { background: #8957e5; color: white; }
    .status-4xx { background: #d29922; color: white; }
    .status-5xx { background: #da3633; color: white; }
    .record-body {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      padding: 16px;
    }
    .flow-col h4 {
      margin: 0 0 8px 0;
      font-size: 12px;
      text-transform: uppercase;
      color: var(--text-muted);
    }
    .code-block {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 12px;
      margin: 0;
      font-family: Consolas, monospace;
      font-size: 11px;
      max-height: 350px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .record-footer {
      padding: 8px 16px;
      background: rgba(0, 0, 0, 0.2);
      border-top: 1px solid var(--border);
      font-size: 11px;
      color: var(--text-muted);
    }
    footer {
      text-align: center;
      margin-top: 40px;
      font-size: 12px;
      color: var(--text-muted);
    }
    footer a { color: var(--link); text-decoration: none; }
  </style>
</head>
<body>
  <header>
    <h1>RequestVault Evidence Report</h1>
    <div class="meta-bar">
      <span>Export Date: ${dateStr}</span> |
      <span>Total Captured Records: ${targets.length}</span> |
      <span>Redaction Applied: ${options.redactSecrets ? "YES" : "NO"}</span>
    </div>
  </header>

  <main>
    ${rowsHtml}
  </main>

  <footer>
    <p>Generated by RequestVault for Caido - <a href="https://bhavymorvadiya.netlify.app/" target="_blank">bhavymorvadiya.netlify.app</a></p>
  </footer>
</body>
</html>`;
  }

  // -------------------------------------------------------------
  // 2. Markdown VAPT Dossier
  // -------------------------------------------------------------
  public static generateMarkdown(records: TrafficRecord[], options: ExportOptions): string {
    const targets = options.redactSecrets ? records.map(r => Redactor.redactRecord(r)) : records;
    const dateStr = new Date().toISOString().split("T")[0];

    const lines: string[] = [
      "# RequestVault Traffic Export",
      "",
      `**Export Date:** ${dateStr}  `,
      `**Total Requests:** ${targets.length}  `,
      `**Secrets Redacted:** ${options.redactSecrets ? "Yes" : "No"}  `,
      "",
      "---",
      "",
      "## Summary of Captured Endpoints",
      "",
      "| # | Method | Status | Host | Path | MIME | Size |",
      "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ];

    for (const r of targets) {
      lines.push(`| #${r.sequenceNumber} | ${r.method} | ${r.statusCode || "-"} | ${r.host} | \`${r.path}\` | ${r.contentType || "-"} | ${r.responseSize} B |`);
    }

    lines.push("");
    lines.push("---");
    lines.push("");

    for (const r of targets) {
      lines.push(`### TRANSACTION NO. ${r.sequenceNumber}`);
      lines.push("");
      lines.push(`**Method:** ${r.method}  `);
      lines.push(`**URL:** \`${r.url}\`  `);
      lines.push(`**Status Code:** ${r.statusCode || "-"} ${r.statusReason || ""}  `);
      lines.push(`**Duration:** ${r.durationMs} ms  `);
      lines.push(`**SHA-256 (Req):** \`${r.requestHash || "-"}\`  `);
      lines.push(`**SHA-256 (Resp):** \`${r.responseHash || "-"}\`  `);
      lines.push("");

      lines.push("#### Request");
      lines.push("```http");
      lines.push(`${r.method} ${r.path} HTTP/1.1`);
      if (r.requestHeaders) {
        for (const h of r.requestHeaders) lines.push(h);
      }
      lines.push("");
      if (r.requestBody) lines.push(r.requestBody);
      lines.push("```");
      lines.push("");

      lines.push("#### Response");
      lines.push("```http");
      lines.push(`HTTP/1.1 ${r.statusCode} ${r.statusReason || ""}`);
      if (r.responseHeaders) {
        for (const h of r.responseHeaders) lines.push(h);
      }
      lines.push("");
      if (r.responseBody) lines.push(r.responseBody);
      lines.push("```");
      lines.push("");
      lines.push("---");
      lines.push("");
    }

    lines.push("<p align=\"center\">Generated by <a href=\"https://bhavymorvadiya.netlify.app/\">bhavymorvadiya.netlify.app</a></p>");
    return lines.join("\n");
  }

  // -------------------------------------------------------------
  // 3. JSON Evidence Format
  // -------------------------------------------------------------
  public static generateJson(records: TrafficRecord[], options: ExportOptions): string {
    const targets = options.redactSecrets ? records.map(r => Redactor.redactRecord(r)) : records;
    return JSON.stringify({
      version: "1.0.0",
      generator: "RequestVault for Caido",
      exportedAt: new Date().toISOString(),
      redacted: options.redactSecrets,
      totalCount: targets.length,
      records: targets
    }, null, 2);
  }

  // -------------------------------------------------------------
  // 4. CSV Triage Format
  // -------------------------------------------------------------
  public static generateCsv(records: TrafficRecord[]): string {
    const headers = [
      "SequenceNumber",
      "Method",
      "Host",
      "Port",
      "Protocol",
      "Path",
      "StatusCode",
      "ContentType",
      "RequestSize",
      "ResponseSize",
      "DurationMs",
      "RequestHash",
      "ResponseHash",
      "URL"
    ];

    const lines: string[] = [headers.join(",")];
    for (const r of records) {
      const row = [
        r.sequenceNumber,
        this.escapeCsv(r.method),
        this.escapeCsv(r.host),
        r.port,
        r.isTls ? "HTTPS" : "HTTP",
        this.escapeCsv(r.path),
        r.statusCode || "",
        this.escapeCsv(r.contentType || ""),
        r.requestSize,
        r.responseSize,
        r.durationMs,
        this.escapeCsv(r.requestHash || ""),
        this.escapeCsv(r.responseHash || ""),
        this.escapeCsv(r.url)
      ];
      lines.push(row.join(","));
    }
    return lines.join("\n");
  }

  // -------------------------------------------------------------
  // 5. HAR 1.2 Format
  // -------------------------------------------------------------
  public static generateHar(records: TrafficRecord[], options: ExportOptions): string {
    const targets = options.redactSecrets ? records.map(r => Redactor.redactRecord(r)) : records;
    const entries = targets.map(r => {
      const reqHeaders = (r.requestHeaders || []).map(h => {
        const colon = h.indexOf(":");
        return {
          name: colon > 0 ? h.substring(0, colon).trim() : h,
          value: colon > 0 ? h.substring(colon + 1).trim() : ""
        };
      });

      const respHeaders = (r.responseHeaders || []).map(h => {
        const colon = h.indexOf(":");
        return {
          name: colon > 0 ? h.substring(0, colon).trim() : h,
          value: colon > 0 ? h.substring(colon + 1).trim() : ""
        };
      });

      return {
        startedDateTime: new Date(r.timestamp).toISOString(),
        time: r.durationMs,
        request: {
          method: r.method,
          url: r.url,
          httpVersion: "HTTP/1.1",
          headers: reqHeaders,
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: r.requestSize,
          postData: r.requestBody ? {
            mimeType: "application/octet-stream",
            text: r.requestBody
          } : undefined
        },
        response: {
          status: r.statusCode,
          statusText: r.statusReason || "",
          httpVersion: "HTTP/1.1",
          headers: respHeaders,
          cookies: [],
          content: {
            size: r.responseSize,
            mimeType: r.contentType || "application/octet-stream",
            text: r.responseBody
          },
          redirectURL: "",
          headersSize: -1,
          bodySize: r.responseSize
        },
        cache: {},
        timings: {
          send: 0,
          wait: r.durationMs,
          receive: 0
        }
      };
    });

    return JSON.stringify({
      log: {
        version: "1.2",
        creator: {
          name: "RequestVault for Caido",
          version: "1.0.0"
        },
        entries: entries
      }
    }, null, 2);
  }

  // -------------------------------------------------------------
  // 6. SHA-256 Audit Evidence Manifest
  // -------------------------------------------------------------
  public static async generateManifest(records: TrafficRecord[], exportFileName: string, fileContent: string): Promise<string> {
    const fileHash = await this.calculateSha256(fileContent);
    const recordHashes = await Promise.all(records.map(async r => ({
      sequenceNumber: r.sequenceNumber,
      url: r.url,
      method: r.method,
      requestHash: r.requestHash || (await this.calculateSha256(r.rawRequest || r.requestBody || "")),
      responseHash: r.responseHash || (await this.calculateSha256(r.rawResponse || r.responseBody || ""))
    })));

    return JSON.stringify({
      manifestVersion: "1.0.0",
      createdTimestamp: new Date().toISOString(),
      tool: "RequestVault for Caido",
      auditorWebsite: "https://bhavymorvadiya.netlify.app/",
      exportedArtifact: {
        fileName: exportFileName,
        sha256: fileHash,
        byteCount: new TextEncoder().encode(fileContent).length
      },
      itemCount: records.length,
      records: recordHashes
    }, null, 2);
  }

  private static escapeHtml(s: string): string {
    if (!s) return "";
    return s.replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  private static escapeCsv(s: string): string {
    if (!s) return '""';
    if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return '"' + s + '"';
  }
}

