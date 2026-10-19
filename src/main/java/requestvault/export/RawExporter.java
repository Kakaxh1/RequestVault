package requestvault.export;

import requestvault.model.TrafficRecord;
import requestvault.storage.EvidenceManifest;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class RawExporter implements TrafficExporter {

    @Override
    public String formatName() {
        return "RAW HTTP";
    }

    @Override
    public String fileExtension() {
        return ".txt";
    }

    @Override
    public ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException {
        ExportResult result = new ExportResult(destination.getAbsolutePath());

        if (options.isSeparateFiles()) {
            File baseDir = destination.isDirectory() ? destination : destination.getParentFile();
            if (baseDir == null) baseDir = new File(".");

            for (int i = 0; i < records.size(); i++) {
                TrafficRecord r = records.get(i);
                try {
                    String prefix = String.format("%04d_%s", i + 1, r.getMethod());
                    File reqFile = new File(baseDir, prefix + "_req.bin");
                    File resFile = new File(baseDir, prefix + "_resp.bin");

                    byte[] reqBytes = options.isRedactSecrets()
                            ? options.getRedactionEngine().redactBytes(r.getRequestBytes(), r.getRequestBodyOffset(), r.getRequestHeaders())
                            : r.getRequestBytes();

                    try (FileOutputStream fos = new FileOutputStream(reqFile)) {
                        fos.write(reqBytes);
                    }
                    result.addGeneratedFile(reqFile);

                    if (r.hasResponse()) {
                        byte[] resBytes = options.isRedactSecrets()
                                ? options.getRedactionEngine().redactBytes(r.getResponseBytes(), r.getResponseBodyOffset(), r.getResponseHeaders())
                                : r.getResponseBytes();
                        try (FileOutputStream fos = new FileOutputStream(resFile)) {
                            fos.write(resBytes);
                        }
                        result.addGeneratedFile(resFile);
                    }
                    result.setExportedCount(result.getExportedCount() + 1);
                } catch (Exception e) {
                    result.setSkippedCount(result.getSkippedCount() + 1);
                    result.addError("Error writing raw files for record " + r.getRecordId() + ": " + e.getMessage());
                }
            }
        } else {
            // Single consolidated stream file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(destination, StandardCharsets.UTF_8))) {
                for (int i = 0; i < records.size(); i++) {
                    TrafficRecord r = records.get(i);
                    try {
                        writer.write("================================================================================\n");
                        writer.write(String.format("TRANSACTION #%d [%s] - %s %s\n", i + 1, r.getRecordId(), r.getMethod(), r.getUrl()));
                        writer.write(String.format("HOST: %s:%d | PROTOCOL: %s | SOURCE: %s\n", r.getHost(), r.getPort(), r.getProtocol(), r.getSourceTool()));
                        writer.write(String.format("REQUEST SHA-256:  %s\n", r.getRequestHash()));
                        writer.write(String.format("RESPONSE SHA-256: %s\n", r.getResponseHash() != null ? r.getResponseHash() : "NONE"));
                        writer.write("================================================================================\n\n");

                        // Request
                        writer.write("----- HTTP REQUEST -----\n");
                        List<String> reqHeaders = options.isRedactSecrets()
                                ? options.getRedactionEngine().redactHeaders(r.getRequestHeaders())
                                : r.getRequestHeaders();
                        for (String h : reqHeaders) {
                            writer.write(h);
                            writer.write("\r\n");
                        }
                        writer.write("\r\n");
                        String reqBody = options.isRedactSecrets()
                                ? options.getRedactionEngine().redactBody(r.getRequestBodyAsString())
                                : r.getRequestBodyAsString();
                        writer.write(reqBody);
                        writer.write("\n\n");

                        // Response
                        writer.write(String.format("----- HTTP RESPONSE (Status: %d %s) -----\n", r.getStatusCode(), r.getStatusReason()));
                        if (r.hasResponse()) {
                            List<String> resHeaders = options.isRedactSecrets()
                                    ? options.getRedactionEngine().redactHeaders(r.getResponseHeaders())
                                    : r.getResponseHeaders();
                            for (String h : resHeaders) {
                                writer.write(h);
                                writer.write("\r\n");
                            }
                            writer.write("\r\n");
                            String resBody = options.isRedactSecrets()
                                    ? options.getRedactionEngine().redactBody(r.getResponseBodyAsString())
                                    : r.getResponseBodyAsString();
                            writer.write(resBody);
                            writer.write("\n\n\n");
                        } else {
                            writer.write("[NO RESPONSE RECORDED]\n\n\n");
                        }

                        result.setExportedCount(result.getExportedCount() + 1);
                    } catch (Exception e) {
                        result.setSkippedCount(result.getSkippedCount() + 1);
                        result.addError("Error writing stream record " + r.getRecordId() + ": " + e.getMessage());
                    }
                }
            }
            result.addGeneratedFile(destination);
        }

        if (options.isGenerateManifest()) {
            File parentDir = destination.isDirectory() ? destination : destination.getParentFile();
            if (parentDir == null) parentDir = new File(".");
            File manifestFile = EvidenceManifest.writeManifest(parentDir, result.getGeneratedFiles(), records, options.isRedactSecrets());
            result.setManifestFile(manifestFile);
        }

        return result;
    }
}
