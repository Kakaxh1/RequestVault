package requestvault.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import requestvault.model.TrafficRecord;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ClipboardHelper {

    public static void copyToClipboard(String content) {
        StringSelection selection = new StringSelection(content != null ? content : "");
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    public static void copyAsJson(List<TrafficRecord> records, boolean redact) {
        ExportOptions options = new ExportOptions();
        options.setRedactSecrets(redact);
        List<Map<String, Object>> data = new ArrayList<>();

        for (TrafficRecord r : records) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("sequence", r.getSequenceNumber());
            item.put("recordId", r.getRecordId());
            item.put("method", r.getMethod());
            item.put("url", r.getUrl());
            item.put("statusCode", r.getStatusCode());
            item.put("statusReason", r.getStatusReason());

            Map<String, Object> req = new LinkedHashMap<>();
            req.put("headers", options.isRedactSecrets() ? options.getRedactionEngine().redactHeaders(r.getRequestHeaders()) : r.getRequestHeaders());
            req.put("body", options.isRedactSecrets() ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString()) : r.getRequestBodyAsString());
            item.put("request", req);

            Map<String, Object> res = new LinkedHashMap<>();
            if (r.hasResponse()) {
                res.put("headers", options.isRedactSecrets() ? options.getRedactionEngine().redactHeaders(r.getResponseHeaders()) : r.getResponseHeaders());
                res.put("body", options.isRedactSecrets() ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString()) : r.getResponseBodyAsString());
            } else {
                res.put("body", null);
            }
            item.put("response", res);
            data.add(item);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        copyToClipboard(gson.toJson(data));
    }

    public static void copyAsCsv(List<TrafficRecord> records) {
        StringBuilder sb = new StringBuilder();
        sb.append("Sequence,Method,Protocol,Host,Port,Path,StatusCode,ContentType,ReqSizeBytes,RespSizeBytes,DurationMs,Source\n");
        for (TrafficRecord r : records) {
            sb.append(r.getSequenceNumber()).append(",");
            sb.append(escapeCsv(r.getMethod())).append(",");
            sb.append(escapeCsv(r.getProtocol())).append(",");
            sb.append(escapeCsv(r.getHost())).append(",");
            sb.append(r.getPort()).append(",");
            sb.append(escapeCsv(r.getPath())).append(",");
            sb.append(r.getStatusCode()).append(",");
            sb.append(escapeCsv(r.getContentType())).append(",");
            sb.append(r.getRequestSize()).append(",");
            sb.append(r.getResponseSize()).append(",");
            sb.append(r.getDurationMs()).append(",");
            sb.append(escapeCsv(r.getSourceTool())).append("\n");
        }
        copyToClipboard(sb.toString());
    }

    public static void copyAsHtml(List<TrafficRecord> records, boolean redact) {
        HtmlExporter exporter = new HtmlExporter();
        ExportOptions options = new ExportOptions();
        options.setRedactSecrets(redact);
        String html = exporter.generateHtml(records, options);
        copyToClipboard(html);
    }

    public static void copyAsMarkdown(List<TrafficRecord> records, boolean redact) {
        MarkdownExporter exporter = new MarkdownExporter();
        ExportOptions options = new ExportOptions();
        options.setRedactSecrets(redact);
        String md = exporter.generateMarkdown(records, options);
        copyToClipboard(md);
    }

    public static void copyAsCurl(List<TrafficRecord> records) {
        copyToClipboard(ReplayCodeGenerator.toCurl(records));
    }

    public static void copyAsPython(List<TrafficRecord> records) {
        copyToClipboard(ReplayCodeGenerator.toPython(records));
    }

    public static void copyAsFetch(List<TrafficRecord> records) {
        copyToClipboard(ReplayCodeGenerator.toFetch(records));
    }

    public static void copyAsPowerShell(List<TrafficRecord> records) {
        copyToClipboard(ReplayCodeGenerator.toPowerShell(records));
    }

    public static void copyAsRawHttp(List<TrafficRecord> records) {
        copyToClipboard(ReplayCodeGenerator.toRawHttp(records));
    }

    private static String escapeCsv(String val) {
        if (val == null) return "\"\"";
        if (val.contains(",") || val.contains("\"") || val.contains("\n") || val.contains("\r")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return "\"" + val + "\"";
    }
}
