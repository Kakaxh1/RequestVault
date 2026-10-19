package requestvault.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import requestvault.model.TrafficRecord;
import requestvault.storage.EvidenceManifest;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HarExporter implements TrafficExporter {

    @Override
    public String formatName() {
        return "HAR 1.2";
    }

    @Override
    public String fileExtension() {
        return ".har";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());

        Map<String, Object> har = new LinkedHashMap<>();
        Map<String, Object> log = new LinkedHashMap<>();
        log.put("version", "1.2");

        Map<String, String> creator = new LinkedHashMap<>();
        creator.put("name", "RequestVault");
        creator.put("version", "0.1.0-MVP");
        log.put("creator", creator);

        List<Map<String, Object>> entries = new ArrayList<>();

        for (TrafficRecord r : records) {
            try {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("startedDateTime", Instant.ofEpochMilli(r.getRequestTimestamp() > 0 ? r.getRequestTimestamp() : System.currentTimeMillis()).toString());
                entry.put("time", Math.max(0, r.getDurationMs()));

                // Request
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("method", r.getMethod());
                req.put("url", r.getUrl());
                req.put("httpVersion", "HTTP/1.1");
                req.put("headers", parseHeadersToHar(r.getRequestHeaders(), options));
                req.put("queryString", new ArrayList<>());
                req.put("cookies", new ArrayList<>());
                req.put("headersSize", -1);
                req.put("bodySize", r.getRequestSize());

                String reqBody = options.isRedactSecrets() 
                        ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString())
                        : r.getRequestBodyAsString();
                if (!reqBody.isEmpty()) {
                    Map<String, Object> postData = new LinkedHashMap<>();
                    postData.put("mimeType", "application/octet-stream");
                    postData.put("text", reqBody);
                    req.put("postData", postData);
                }
                entry.put("request", req);

                // Response
                Map<String, Object> res = new LinkedHashMap<>();
                res.put("status", r.getStatusCode());
                res.put("statusText", r.getStatusReason());
                res.put("httpVersion", "HTTP/1.1");
                res.put("headers", parseHeadersToHar(r.getResponseHeaders(), options));
                res.put("cookies", new ArrayList<>());

                Map<String, Object> content = new LinkedHashMap<>();
                content.put("size", r.getResponseSize());
                content.put("mimeType", r.getContentType().isEmpty() ? "text/plain" : r.getContentType());
                String resBody = options.isRedactSecrets()
                        ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString())
                        : r.getResponseBodyAsString();
                content.put("text", resBody);
                res.put("content", content);
                res.put("redirectURL", "");
                res.put("headersSize", -1);
                res.put("bodySize", r.getResponseSize());
                entry.put("response", res);

                // Timings
                Map<String, Object> timings = new LinkedHashMap<>();
                timings.put("send", 0);
                timings.put("wait", r.getDurationMs());
                timings.put("receive", 0);
                entry.put("timings", timings);

                entries.add(entry);
                result.setExportedCount(result.getExportedCount() + 1);
            } catch (Exception e) {
                result.setSkippedCount(result.getSkippedCount() + 1);
                result.addError("Error formatting HAR entry for " + r.getRecordId() + ": " + e.getMessage());
            }
        }

        log.put("entries", entries);
        har.put("log", log);

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        try (FileWriter writer = new FileWriter(destination)) {
            gson.toJson(har, writer);
        }
        result.addGeneratedFile(destination);

        if (options.isGenerateManifest()) {
            File parentDir = destination.getParentFile() != null ? destination.getParentFile() : new File(".");
            File manifestFile = EvidenceManifest.writeManifest(parentDir, result.getGeneratedFiles(), records, options.isRedactSecrets());
            result.setManifestFile(manifestFile);
        }

        return result;
    }

    private List<Map<String, String>> parseHeadersToHar(List<String> rawHeaders, ExportOptions options) {
        List<Map<String, String>> list = new ArrayList<>();
        List<String> processed = options.isRedactSecrets() 
                ? options.getRedactionEngine().redactHeaders(rawHeaders)
                : rawHeaders;

        for (String h : processed) {
            int colon = h.indexOf(':');
            if (colon > 0) {
                Map<String, String> item = new LinkedHashMap<>();
                item.put("name", h.substring(0, colon).trim());
                item.put("value", h.substring(colon + 1).trim());
                list.add(item);
            }
        }
        return list;
    }
}
