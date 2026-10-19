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
import java.time.LocalDate;
import java.util.List;

public class MarkdownExporter implements TrafficExporter {

    private final Gson prettyGson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    @Override
    public String formatName() {
        return "Markdown Report";
    }

    @Override
    public String fileExtension() {
        return ".md";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());
        String md = generateMarkdown(records, options);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(destination, StandardCharsets.UTF_8))) {
            writer.write(md);
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

    public String generateMarkdown(List<TrafficRecord> records, ExportOptions options) {
        StringBuilder sb = new StringBuilder();

        String project = "Target Application VAPT";
        String target = "https://target.example";
        if (records != null && !records.isEmpty()) {
            TrafficRecord first = records.get(0);
            if (first.getEngagementId() != null && !first.getEngagementId().isEmpty()) {
                project = first.getEngagementId();
            }
            target = first.getProtocol() + "://" + first.getHost() + (first.getPort() != 80 && first.getPort() != 443 ? ":" + first.getPort() : "");
        }

        int totalRequests = records != null ? records.size() : 0;
        int responsesCaptured = 0;
        int missingResponses = 0;

        sb.append("# Burp Traffic Export\n\n");
        sb.append("**Project:** ").append(project).append("  \n");
        sb.append("**Target:** `").append(target).append("`  \n");
        sb.append("**Export Date:** ").append(LocalDate.now().toString()).append("  \n");
        sb.append("**Total Requests:** ").append(totalRequests).append("\n\n");
        sb.append("---\n\n");

        if (records != null) {
            for (int i = 0; i < records.size(); i++) {
                TrafficRecord r = records.get(i);
                int reqNum = i + 1;

                if (r.hasResponse()) {
                    responsesCaptured++;
                } else {
                    missingResponses++;
                }

                sb.append("## REQUEST NO. ").append(reqNum).append("\n\n");
                sb.append("**Method:** ").append(r.getMethod()).append("  \n");
                sb.append("**URL:** `").append(r.getUrl()).append("`  \n");
                sb.append("**Status:** ").append(r.getStatusCode() > 0 ? r.getStatusCode() + " " + r.getStatusReason() : "No Response").append("\n\n");

                // Request block
                sb.append("### Request ").append(reqNum).append("\n\n");
                sb.append("```http\n");

                List<String> reqHeaders = options.isRedactSecrets()
                        ? options.getRedactionEngine().redactHeaders(r.getRequestHeaders())
                        : r.getRequestHeaders();

                boolean hasRequestLine = !reqHeaders.isEmpty() && (reqHeaders.get(0).startsWith(r.getMethod() + " ") || reqHeaders.get(0).contains(" HTTP/"));
                if (!hasRequestLine) {
                    sb.append(r.getMethod()).append(" ").append(r.getPath()).append(" HTTP/1.1\n");
                }

                for (String h : reqHeaders) {
                    sb.append(h).append("\n");
                }

                String reqBody = options.isRedactSecrets()
                        ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString())
                        : r.getRequestBodyAsString();

                String formattedReqBody = formatBody(reqBody);
                if (!formattedReqBody.isEmpty()) {
                    sb.append("\n").append(formattedReqBody).append("\n");
                }
                sb.append("```\n\n");

                // Response block
                sb.append("### Response ").append(reqNum).append("\n\n");
                sb.append("```http\n");
                if (r.hasResponse()) {
                    List<String> resHeaders = options.isRedactSecrets()
                            ? options.getRedactionEngine().redactHeaders(r.getResponseHeaders())
                            : r.getResponseHeaders();

                    boolean hasStatusLine = !resHeaders.isEmpty() && resHeaders.get(0).startsWith("HTTP/");
                    if (!hasStatusLine) {
                        sb.append("HTTP/1.1 ").append(r.getStatusCode()).append(" ").append(r.getStatusReason()).append("\n");
                    }

                    for (String h : resHeaders) {
                        sb.append(h).append("\n");
                    }

                    String resBody = options.isRedactSecrets()
                            ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString())
                            : r.getResponseBodyAsString();

                    String formattedResBody = formatBody(resBody);
                    if (!formattedResBody.isEmpty()) {
                        sb.append("\n").append(formattedResBody).append("\n");
                    }
                } else {
                    sb.append("HTTP/1.1 000 No Response\n\n[No response captured]\n");
                }
                sb.append("```\n\n");
                sb.append("---\n\n");
            }
        }

        // Summary block
        sb.append("# Export Summary\n\n");
        sb.append("- Total requests exported: ").append(totalRequests).append("\n");
        sb.append("- Responses captured: ").append(responsesCaptured).append("\n");
        sb.append("- Missing responses: ").append(missingResponses).append("\n");
        sb.append("- Credentials redacted: ").append(options.isRedactSecrets() ? "Yes" : "No").append("\n");
        sb.append("- Request-response pairing: Preserved\n\n");
        sb.append("---\n*Generated by RequestVault · [bhavymorvadiya.netlify.app](https://bhavymorvadiya.netlify.app/)*\n");

        return sb.toString();
    }

    private String formatBody(String body) {
        if (body == null || body.trim().isEmpty()) return "";
        String trimmed = body.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                JsonElement elem = JsonParser.parseString(trimmed);
                return prettyGson.toJson(elem);
            } catch (Exception ignored) {}
        }
        return body;
    }
}
