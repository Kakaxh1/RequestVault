package requestvault.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import requestvault.model.TrafficRecord;
import requestvault.storage.EvidenceManifest;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

public class HtmlExporter implements TrafficExporter {

    private final Gson prettyGson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    @Override
    public String formatName() {
        return "HTML Report";
    }

    @Override
    public String fileExtension() {
        return ".html";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());
        String html = generateHtml(records, options);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(destination, StandardCharsets.UTF_8))) {
            writer.write(html);
        }
        result.setExportedCount(records.size());
        result.addGeneratedFile(destination);

        if (options.isGenerateManifest()) {
            File parentDir = destination.getParentFile() != null ? destination.getParentFile() : new File(".");
            File manifestFile = EvidenceManifest.writeManifest(parentDir, result.getGeneratedFiles(), records, options.isRedactSecrets());
            result.setManifestFile(manifestFile);
        }

        return result;
    }

    public String generateHtml(List<TrafficRecord> records, ExportOptions options) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n");
        sb.append("<title>RequestVault - HTTP Traffic Evidence</title>\n");
        sb.append("<style>\n");
        sb.append("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 24px; background: #f8f9fa; color: #212529; }\n");
        sb.append("h1, h2, h3 { color: #1a1a1a; }\n");
        sb.append(".header-box { background: #fff; padding: 18px; border-radius: 8px; border: 1px solid #dee2e6; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }\n");
        sb.append("table { width: 100%; border-collapse: collapse; margin: 16px 0; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }\n");
        sb.append("th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #dee2e6; font-size: 13px; }\n");
        sb.append("th { background: #f1f3f5; font-weight: 600; color: #495057; }\n");
        sb.append(".badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; }\n");
        sb.append(".badge-get { background: #e3f2fd; color: #0d47a1; }\n");
        sb.append(".badge-post { background: #e8f5e9; color: #1b5e20; }\n");
        sb.append(".badge-put { background: #fff3e0; color: #e65100; }\n");
        sb.append(".badge-delete { background: #ffebee; color: #b71c1c; }\n");
        sb.append(".badge-status { font-weight: bold; border-radius: 3px; padding: 2px 6px; }\n");
        sb.append(".status-2xx { background: #e8f5e9; color: #2e7d32; }\n");
        sb.append(".status-3xx { background: #e1f5fe; color: #0277bd; }\n");
        sb.append(".status-4xx { background: #fff8e1; color: #f57f17; }\n");
        sb.append(".status-5xx { background: #ffebee; color: #c62828; }\n");
        sb.append(".card { background: #fff; border: 1px solid #dee2e6; border-radius: 8px; padding: 16px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }\n");
        sb.append("pre { background: #282c34; color: #abb2bf; padding: 14px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; line-height: 1.4; }\n");
        sb.append("</style>\n</head>\n<body>\n");

        sb.append("<div class=\"header-box\">\n");
        sb.append("<h1>RequestVault Evidence Pack</h1>\n");
        sb.append("<p><strong>Generated:</strong> ").append(Instant.now().toString()).append(" | <strong>Total Transactions:</strong> ").append(records.size()).append("</p>\n");
        sb.append("<p><strong>Redaction:</strong> ").append(options.isRedactSecrets() ? "<span style='color:green;'>Enabled (Secrets Masked)</span>" : "<span style='color:orange;'>Raw Unredacted</span>").append("</p>\n");
        sb.append("</div>\n");

        // Overview Table
        sb.append("<h2>Traffic Overview</h2>\n");
        sb.append("<table>\n<thead>\n<tr><th>#</th><th>Method</th><th>Status</th><th>Host</th><th>Path</th><th>Size</th><th>Time</th></tr>\n</thead>\n<tbody>\n");
        for (TrafficRecord r : records) {
            String mClass = "badge-get";
            String m = r.getMethod().toUpperCase();
            if ("POST".equals(m)) mClass = "badge-post";
            else if ("PUT".equals(m) || "PATCH".equals(m)) mClass = "badge-put";
            else if ("DELETE".equals(m)) mClass = "badge-delete";

            int code = r.getStatusCode();
            String sClass = "status-2xx";
            if (code >= 300 && code < 400) sClass = "status-3xx";
            else if (code >= 400 && code < 500) sClass = "status-4xx";
            else if (code >= 500) sClass = "status-5xx";

            sb.append("<tr>")
                    .append("<td>#").append(r.getSequenceNumber()).append("</td>")
                    .append("<td><span class=\"badge ").append(mClass).append("\">").append(escape(r.getMethod())).append("</span></td>")
                    .append("<td><span class=\"badge-status ").append(sClass).append("\">").append(r.getStatusCode()).append("</span></td>")
                    .append("<td>").append(escape(r.getHost())).append("</td>")
                    .append("<td><a href=\"#tx-").append(r.getRecordId()).append("\">").append(escape(r.getPath())).append("</a></td>")
                    .append("<td>").append(r.getResponseSize()).append(" B</td>")
                    .append("<td>").append(r.getDurationMs()).append(" ms</td>")
                    .append("</tr>\n");
        }
        sb.append("</tbody>\n</table>\n\n");

        // Detailed Transactions
        sb.append("<h2>Transaction Details</h2>\n");
        for (TrafficRecord r : records) {
            sb.append("<div class=\"card\" id=\"tx-").append(r.getRecordId()).append("\">\n");
            sb.append("<h3>#").append(r.getSequenceNumber()).append(" - ").append(escape(r.getMethod())).append(" ").append(escape(r.getUrl())).append("</h3>\n");
            sb.append("<p><strong>Status:</strong> ").append(r.getStatusCode()).append(" ").append(escape(r.getStatusReason()))
                    .append(" | <strong>Request SHA-256:</strong> <code>").append(r.getRequestHash()).append("</code>")
                    .append(" | <strong>Response SHA-256:</strong> <code>").append(r.getResponseHash() != null ? r.getResponseHash() : "NONE").append("</code></p>\n");

            // Request
            sb.append("<h4>Request</h4>\n<pre>");
            List<String> reqHeaders = options.isRedactSecrets() ? options.getRedactionEngine().redactHeaders(r.getRequestHeaders()) : r.getRequestHeaders();
            for (String h : reqHeaders) sb.append(escape(h)).append("\n");
            sb.append("\n");
            String reqBody = options.isRedactSecrets() ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString()) : r.getRequestBodyAsString();
            sb.append(escape(formatBody(reqBody)));
            sb.append("</pre>\n");

            // Response
            sb.append("<h4>Response</h4>\n<pre>");
            if (r.hasResponse()) {
                List<String> resHeaders = options.isRedactSecrets() ? options.getRedactionEngine().redactHeaders(r.getResponseHeaders()) : r.getResponseHeaders();
                for (String h : resHeaders) sb.append(escape(h)).append("\n");
                sb.append("\n");
                String resBody = options.isRedactSecrets() ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString()) : r.getResponseBodyAsString();
                sb.append(escape(formatBody(resBody)));
            } else {
                sb.append("[No Response Recorded]");
            }
            sb.append("</pre>\n");

            sb.append("</div>\n");
        }

        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private String formatBody(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                JsonElement elem = JsonParser.parseString(trimmed);
                return prettyGson.toJson(elem);
            } catch (Exception ignored) {}
        }
        return body;
    }

    private String escape(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
