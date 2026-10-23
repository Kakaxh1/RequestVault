package requestvault.export;

import requestvault.model.TrafficRecord;

import java.util.List;

/**
 * Multi-Language Exploit and Replay Script Generator for RequestVault.
 * Generates ready-to-execute scripts in:
 * - cURL (bash / terminal command)
 * - Python (requests library with session & SSL bypass)
 * - JavaScript (modern Fetch API for browser console / Node.js)
 * - PowerShell (Invoke-RestMethod with certificate bypass)
 * - Raw HTTP (RFC 7230 wire format)
 */
public class ReplayCodeGenerator {

    // -------------------------------------------------------------
    // 1. cURL Generator
    // -------------------------------------------------------------
    public static String toCurl(TrafficRecord record) {
        if (record == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("curl -i -s -k -X ").append(record.getMethod().toUpperCase()).append(" ");
        sb.append("\"").append(escapeDoubleQuotes(record.getUrl())).append("\"");

        for (String header : record.getRequestHeaders()) {
            if (header == null || header.trim().isEmpty()) continue;
            // Skip pseudo-headers or host if preferred, but keeping all provides exact reproduction
            sb.append(" \\\n  -H \"").append(escapeDoubleQuotes(header)).append("\"");
        }

        String body = record.getRequestBodyAsString();
        if (body != null && !body.isEmpty()) {
            // Use --data-raw with single-quote escaping for bash safety
            String escapedBody = body.replace("'", "'\\''");
            sb.append(" \\\n  --data-raw '").append(escapedBody).append("'");
        }

        return sb.toString();
    }

    public static String toCurl(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) return "";
        if (records.size() == 1) return toCurl(records.get(0));

        StringBuilder sb = new StringBuilder();
        sb.append("#!/usr/bin/env bash\n");
        sb.append("# RequestVault Generated Multi-Step cURL Replay Script\n\n");

        for (int i = 0; i < records.size(); i++) {
            TrafficRecord r = records.get(i);
            sb.append(String.format("# --- Step %d/%d: %s %s (#%d) ---\n",
                    i + 1, records.size(), r.getMethod(), r.getPath(), r.getSequenceNumber()));
            sb.append(toCurl(r)).append("\n\n");
        }
        return sb.toString().trim();
    }

    // -------------------------------------------------------------
    // 2. Python Requests Generator
    // -------------------------------------------------------------
    public static String toPython(TrafficRecord record) {
        if (record == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("import requests\n");
        sb.append("import urllib3\n\n");
        sb.append("# Suppress self-signed certificate warnings for penetration testing\n");
        sb.append("urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n\n");

        sb.append("url = \"").append(escapeDoubleQuotes(record.getUrl())).append("\"\n\n");

        sb.append("headers = {\n");
        for (String h : record.getRequestHeaders()) {
            if (h == null || h.trim().isEmpty()) continue;
            int colon = h.indexOf(':');
            if (colon > 0) {
                String k = h.substring(0, colon).trim();
                String v = h.substring(colon + 1).trim();
                sb.append("    \"").append(escapeDoubleQuotes(k)).append("\": \"")
                        .append(escapeDoubleQuotes(v)).append("\",\n");
            }
        }
        sb.append("}\n\n");

        String body = record.getRequestBodyAsString();
        if (body != null && !body.isEmpty()) {
            sb.append("payload = \"\"\"").append(body.replace("\"\"\"", "\\\"\\\"\\\"")).append("\"\"\"\n\n");
            sb.append(String.format("response = requests.request(\n    method=\"%s\",\n    url=url,\n    headers=headers,\n    data=payload,\n    verify=False\n)\n\n",
                    record.getMethod().toUpperCase()));
        } else {
            sb.append(String.format("response = requests.request(\n    method=\"%s\",\n    url=url,\n    headers=headers,\n    verify=False\n)\n\n",
                    record.getMethod().toUpperCase()));
        }

        sb.append("print(f\"[*] Status: {response.status_code} {response.reason}\")\n");
        sb.append("print(f\"[*] Response Length: {len(response.content)} bytes\")\n");
        sb.append("print(response.text)\n");

        return sb.toString();
    }

    public static String toPython(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) return "";
        if (records.size() == 1) return toPython(records.get(0));

        StringBuilder sb = new StringBuilder();
        sb.append("import requests\n");
        sb.append("import urllib3\n\n");
        sb.append("# RequestVault Multi-Transaction Python Replay Session\n");
        sb.append("urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n\n");
        sb.append("session = requests.Session()\n");
        sb.append("session.verify = False\n\n");

        for (int i = 0; i < records.size(); i++) {
            TrafficRecord r = records.get(i);
            sb.append(String.format("# ==========================================================\n"));
            sb.append(String.format("# Step %d: %s %s (#%d)\n", i + 1, r.getMethod(), r.getPath(), r.getSequenceNumber()));
            sb.append(String.format("# ==========================================================\n"));
            sb.append("url = \"").append(escapeDoubleQuotes(r.getUrl())).append("\"\n");
            sb.append("headers = {\n");
            for (String h : r.getRequestHeaders()) {
                if (h == null || h.trim().isEmpty()) continue;
                int colon = h.indexOf(':');
                if (colon > 0) {
                    String k = h.substring(0, colon).trim();
                    String v = h.substring(colon + 1).trim();
                    sb.append("    \"").append(escapeDoubleQuotes(k)).append("\": \"")
                            .append(escapeDoubleQuotes(v)).append("\",\n");
                }
            }
            sb.append("}\n");

            String body = r.getRequestBodyAsString();
            if (body != null && !body.isEmpty()) {
                sb.append("payload = \"\"\"").append(body.replace("\"\"\"", "\\\"\\\"\\\"")).append("\"\"\"\n");
                sb.append(String.format("r%d = session.request(\"%s\", url, headers=headers, data=payload)\n", i + 1, r.getMethod().toUpperCase()));
            } else {
                sb.append(String.format("r%d = session.request(\"%s\", url, headers=headers)\n", i + 1, r.getMethod().toUpperCase()));
            }
            sb.append(String.format("print(f\"[Step %d] Status: {r%d.status_code}\")\n\n", i + 1, i + 1));
        }

        return sb.toString().trim();
    }

    // -------------------------------------------------------------
    // 3. JavaScript Fetch Generator
    // -------------------------------------------------------------
    public static String toFetch(TrafficRecord record) {
        if (record == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("// RequestVault JavaScript (Fetch API) Replay Snippet\n");
        sb.append("const url = \"").append(escapeDoubleQuotes(record.getUrl())).append("\";\n\n");

        sb.append("const options = {\n");
        sb.append("  method: \"").append(record.getMethod().toUpperCase()).append("\",\n");
        sb.append("  headers: {\n");
        for (String h : record.getRequestHeaders()) {
            if (h == null || h.trim().isEmpty()) continue;
            int colon = h.indexOf(':');
            if (colon > 0) {
                String k = h.substring(0, colon).trim();
                String v = h.substring(colon + 1).trim();
                sb.append("    \"").append(escapeDoubleQuotes(k)).append("\": \"")
                        .append(escapeDoubleQuotes(v)).append("\",\n");
            }
        }
        sb.append("  }");

        String body = record.getRequestBodyAsString();
        if (body != null && !body.isEmpty()) {
            sb.append(",\n  body: ").append(escapeJsString(body)).append("\n");
        } else {
            sb.append("\n");
        }
        sb.append("};\n\n");

        sb.append("fetch(url, options)\n");
        sb.append("  .then(async (response) => {\n");
        sb.append("    console.log(`[*] Status: ${response.status} ${response.statusText}`);\n");
        sb.append("    const text = await response.text();\n");
        sb.append("    console.log(text);\n");
        sb.append("  })\n");
        sb.append("  .catch(err => console.error(\"[!] Request failed:\", err));\n");

        return sb.toString();
    }

    public static String toFetch(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) return "";
        if (records.size() == 1) return toFetch(records.get(0));

        StringBuilder sb = new StringBuilder();
        sb.append("// RequestVault Multi-Step Fetch Runner\n");
        sb.append("async function replayFlow() {\n");

        for (int i = 0; i < records.size(); i++) {
            TrafficRecord r = records.get(i);
            sb.append(String.format("  // Step %d: %s %s (#%d)\n", i + 1, r.getMethod(), r.getPath(), r.getSequenceNumber()));
            sb.append("  {\n");
            sb.append("    const url = \"").append(escapeDoubleQuotes(r.getUrl())).append("\";\n");
            sb.append("    const res = await fetch(url, {\n");
            sb.append("      method: \"").append(r.getMethod().toUpperCase()).append("\",\n");
            sb.append("      headers: {\n");
            for (String h : r.getRequestHeaders()) {
                if (h == null || h.trim().isEmpty()) continue;
                int colon = h.indexOf(':');
                if (colon > 0) {
                    String k = h.substring(0, colon).trim();
                    String v = h.substring(colon + 1).trim();
                    sb.append("        \"").append(escapeDoubleQuotes(k)).append("\": \"")
                            .append(escapeDoubleQuotes(v)).append("\",\n");
                }
            }
            sb.append("      }");
            String body = r.getRequestBodyAsString();
            if (body != null && !body.isEmpty()) {
                sb.append(",\n      body: ").append(escapeJsString(body)).append("\n");
            } else {
                sb.append("\n");
            }
            sb.append("    });\n");
            sb.append(String.format("    console.log(`[Step %d] Status: ${res.status}`);\n", i + 1));
            sb.append("  }\n\n");
        }

        sb.append("}\n\nreplayFlow();\n");
        return sb.toString().trim();
    }

    // -------------------------------------------------------------
    // 4. PowerShell Generator (Invoke-RestMethod)
    // -------------------------------------------------------------
    public static String toPowerShell(TrafficRecord record) {
        if (record == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("# RequestVault PowerShell Replay Script\n");
        sb.append("$headers = @{\n");
        for (String h : record.getRequestHeaders()) {
            if (h == null || h.trim().isEmpty()) continue;
            int colon = h.indexOf(':');
            if (colon > 0) {
                String k = h.substring(0, colon).trim();
                String v = h.substring(colon + 1).trim();
                sb.append("    \"").append(escapeDoubleQuotes(k)).append("\" = \"")
                        .append(escapeDoubleQuotes(v)).append("\"\n");
            }
        }
        sb.append("}\n\n");

        String body = record.getRequestBodyAsString();
        if (body != null && !body.isEmpty()) {
            sb.append("$body = @\"\n").append(body).append("\n\"@\n\n");
            sb.append(String.format("$response = Invoke-RestMethod -Uri \"%s\" -Method %s -Headers $headers -Body $body -SkipCertificateCheck\n",
                    record.getUrl(), record.getMethod().toUpperCase()));
        } else {
            sb.append(String.format("$response = Invoke-RestMethod -Uri \"%s\" -Method %s -Headers $headers -SkipCertificateCheck\n",
                    record.getUrl(), record.getMethod().toUpperCase()));
        }
        sb.append("$response | Format-List\n");

        return sb.toString();
    }

    public static String toPowerShell(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) return "";
        if (records.size() == 1) return toPowerShell(records.get(0));

        StringBuilder sb = new StringBuilder();
        sb.append("# RequestVault PowerShell Multi-Step Script\n\n");
        for (int i = 0; i < records.size(); i++) {
            TrafficRecord r = records.get(i);
            sb.append(String.format("# --- Step %d: %s %s (#%d) ---\n", i + 1, r.getMethod(), r.getPath(), r.getSequenceNumber()));
            sb.append(toPowerShell(r)).append("\n");
        }
        return sb.toString().trim();
    }

    // -------------------------------------------------------------
    // 5. Raw HTTP Wire Format (RFC 7230)
    // -------------------------------------------------------------
    public static String toRawHttp(TrafficRecord record) {
        if (record == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(record.getMethod().toUpperCase()).append(" ").append(record.getPath()).append(" HTTP/1.1\r\n");
        for (String h : record.getRequestHeaders()) {
            sb.append(h).append("\r\n");
        }
        sb.append("\r\n");
        String body = record.getRequestBodyAsString();
        if (body != null && !body.isEmpty()) {
            sb.append(body);
        }
        return sb.toString();
    }

    public static String toRawHttp(List<TrafficRecord> records) {
        if (records == null || records.isEmpty()) return "";
        if (records.size() == 1) return toRawHttp(records.get(0));

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < records.size(); i++) {
            TrafficRecord r = records.get(i);
            sb.append("### Transaction #").append(r.getSequenceNumber())
                    .append(" (").append(r.getMethod()).append(" ").append(r.getPath()).append(")\n");
            sb.append(toRawHttp(r));
            sb.append("\n\n");
        }
        return sb.toString().trim();
    }

    // -------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------
    private static String escapeDoubleQuotes(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String escapeJsString(String str) {
        if (str == null) return "\"\"";
        return "\"" + str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }
}
