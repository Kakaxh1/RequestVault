package requestvault.export;

import requestvault.model.TrafficRecord;
import requestvault.storage.EvidenceManifest;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class CsvExporter implements TrafficExporter {

    @Override
    public String formatName() {
        return "CSV";
    }

    @Override
    public String fileExtension() {
        return ".csv";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(destination, StandardCharsets.UTF_8))) {
            // CSV Header
            writer.write("RecordId,Method,Protocol,Host,Port,Path,StatusCode,ContentType,ReqSizeBytes,RespSizeBytes,DurationMs,Source,RequestSha256,ResponseSha256\n");

            for (TrafficRecord r : records) {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append(escapeCsv(r.getRecordId())).append(",");
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
                    sb.append(escapeCsv(r.getSourceTool())).append(",");
                    sb.append(escapeCsv(r.getRequestHash())).append(",");
                    sb.append(escapeCsv(r.getResponseHash() != null ? r.getResponseHash() : ""));
                    sb.append("\n");

                    writer.write(sb.toString());
                    result.setExportedCount(result.getExportedCount() + 1);
                } catch (Exception e) {
                    result.setSkippedCount(result.getSkippedCount() + 1);
                    result.addError("Error writing CSV record " + r.getRecordId() + ": " + e.getMessage());
                }
            }
        }

        result.addGeneratedFile(destination);

        if (options.isGenerateManifest()) {
            File parentDir = destination.getParentFile() != null ? destination.getParentFile() : new File(".");
            File manifestFile = EvidenceManifest.writeManifest(parentDir, result.getGeneratedFiles(), records, options.isRedactSecrets());
            result.setManifestFile(manifestFile);
        }

        return result;
    }

    private String escapeCsv(String val) {
        if (val == null) return "\"\"";
        if (val.contains(",") || val.contains("\"") || val.contains("\n") || val.contains("\r")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return "\"" + val + "\"";
    }
}
