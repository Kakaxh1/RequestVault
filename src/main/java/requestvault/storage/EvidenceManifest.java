package requestvault.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import requestvault.model.TrafficRecord;
import requestvault.security.HashService;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class EvidenceManifest {

    public static File writeManifest(File outputDir, List<File> exportedFiles, List<TrafficRecord> records, boolean redacted) throws IOException {
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("tool", "RequestVault");
        manifest.put("version", "0.1.0-MVP");
        manifest.put("timestamp", Instant.now().toString());
        manifest.put("redacted", redacted);
        manifest.put("recordCount", records.size());

        List<Map<String, Object>> fileEntries = new ArrayList<>();
        for (File f : exportedFiles) {
            if (f != null && f.exists() && f.isFile()) {
                byte[] bytes = Files.readAllBytes(f.toPath());
                Map<String, Object> fe = new LinkedHashMap<>();
                fe.put("fileName", f.getName());
                fe.put("sizeBytes", bytes.length);
                fe.put("sha256", HashService.sha256(bytes));
                fileEntries.add(fe);
            }
        }
        manifest.put("exportedArtifacts", fileEntries);

        List<Map<String, Object>> recordIndex = new ArrayList<>();
        for (TrafficRecord r : records) {
            Map<String, Object> re = new LinkedHashMap<>();
            re.put("recordId", r.getRecordId());
            re.put("method", r.getMethod());
            re.put("url", r.getUrl());
            re.put("statusCode", r.getStatusCode());
            re.put("requestSha256", r.getRequestHash());
            re.put("responseSha256", r.getResponseHash());
            recordIndex.add(re);
        }
        manifest.put("trafficRecords", recordIndex);

        File manifestFile = new File(outputDir, "evidence-manifest.json");
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(manifestFile)) {
            gson.toJson(manifest, writer);
        }

        return manifestFile;
    }
}
