package requestvault.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import requestvault.model.TrafficRecord;
import requestvault.storage.EvidenceManifest;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JsonExporter implements TrafficExporter {

    @Override
    public String formatName() {
        return "JSON";
    }

    @Override
    public String fileExtension() {
        return ".json";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());
        List<Map<String, Object>> exportData = new ArrayList<>();

        for (TrafficRecord r : records) {
            try {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("recordId", r.getRecordId());
                item.put("engagementId", r.getEngagementId());
                item.put("method", r.getMethod());
                item.put("url", r.getUrl());
                item.put("host", r.getHost());
                item.put("port", r.getPort());
                item.put("protocol", r.getProtocol());
                item.put("sourceTool", r.getSourceTool());
                item.put("requestTimestamp", r.getRequestTimestamp());

                // Request
                Map<String, Object> reqObj = new LinkedHashMap<>();
                List<String> reqHeaders = options.isRedactSecrets() 
                        ? options.getRedactionEngine().redactHeaders(r.getRequestHeaders())
                        : r.getRequestHeaders();
                String reqBody = options.isRedactSecrets()
                        ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString())
                        : r.getRequestBodyAsString();

                reqObj.put("headers", reqHeaders);
                reqObj.put("body", reqBody);
                reqObj.put("rawSha256", r.getRequestHash());
                item.put("request", reqObj);

                // Response
                Map<String, Object> resObj = new LinkedHashMap<>();
                resObj.put("statusCode", r.getStatusCode());
                resObj.put("statusReason", r.getStatusReason());
                resObj.put("contentType", r.getContentType());
                resObj.put("responseTimestamp", r.getResponseTimestamp());
                resObj.put("durationMs", r.getDurationMs());

                if (r.hasResponse()) {
                    List<String> resHeaders = options.isRedactSecrets()
                            ? options.getRedactionEngine().redactHeaders(r.getResponseHeaders())
                            : r.getResponseHeaders();
                    String resBody = options.isRedactSecrets()
                            ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString())
                            : r.getResponseBodyAsString();

                    resObj.put("headers", resHeaders);
                    resObj.put("body", resBody);
                    resObj.put("rawSha256", r.getResponseHash());
                } else {
                    resObj.put("body", null);
                    result.addWarning("Record " + r.getRecordId() + " has no response bytes.");
                }
                item.put("response", resObj);
                item.put("redacted", options.isRedactSecrets());

                exportData.add(item);
                result.setExportedCount(result.getExportedCount() + 1);

            } catch (Exception e) {
                result.setSkippedCount(result.getSkippedCount() + 1);
                result.addError("Failed to parse record " + r.getRecordId() + ": " + e.getMessage());
            }
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        try (FileWriter writer = new FileWriter(destination)) {
            gson.toJson(exportData, writer);
        }
        result.addGeneratedFile(destination);

        if (options.isGenerateManifest()) {
            File parentDir = destination.getParentFile() != null ? destination.getParentFile() : new File(".");
            File manifestFile = EvidenceManifest.writeManifest(parentDir, result.getGeneratedFiles(), records, options.isRedactSecrets());
            result.setManifestFile(manifestFile);
        }

        return result;
    }
}
