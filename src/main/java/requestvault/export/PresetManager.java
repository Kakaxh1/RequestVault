package requestvault.export;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;

/**
 * Manages built-in and user-custom export presets for RequestVault.
 * Presets automatically configure formats, redaction policies, file splitting, and SHA-256 manifests.
 */
public class PresetManager {

    private static final String PREF_KEY_CUSTOM_PRESETS = "custom_export_presets";
    private static final Gson gson = new Gson();
    private static final Preferences prefs = Preferences.userNodeForPackage(PresetManager.class);

    private static final Map<String, ExportPreset> BUILT_IN_PRESETS = new LinkedHashMap<>();

    static {
        // 1. Full VAPT Evidence Pack
        BUILT_IN_PRESETS.put("Full VAPT Evidence Pack (HTML + SHA-256)", new ExportPreset(
                "Full VAPT Evidence Pack (HTML + SHA-256)",
                "Standalone interactive HTML report with SHA-256 evidence manifest and credentials redacted.",
                "HTML Report (.html)", true, true, false, true, true
        ));

        // 2. Executive Markdown Report
        BUILT_IN_PRESETS.put("Executive Markdown Dossier (.md)", new ExportPreset(
                "Executive Markdown Dossier (.md)",
                "Formatted Markdown report with endpoint tables and beautified request/response code blocks.",
                "Markdown Report (.md)", true, true, false, true, true
        ));

        // 3. Automated Ingestion & Forensics
        BUILT_IN_PRESETS.put("Structured JSON Evidence (.json)", new ExportPreset(
                "Structured JSON Evidence (.json)",
                "Comprehensive JSON export with metadata, bodies, timestamps, and integrity hashes.",
                "JSON (.json)", true, true, false, false, true
        ));

        // 4. Raw Traffic Forensics (TXT)
        BUILT_IN_PRESETS.put("Forensic Raw Wire Stream (.txt)", new ExportPreset(
                "Forensic Raw Wire Stream (.txt)",
                "Exact byte-for-byte wire transactions with delimiters, unredacted, with SHA-256 manifest.",
                "RAW HTTP Stream (.txt)", false, true, false, false, true
        ));

        // 5. Cross-Tool Interoperability (HAR 1.2)
        BUILT_IN_PRESETS.put("Tool Interoperability Archive (.har)", new ExportPreset(
                "Tool Interoperability Archive (.har)",
                "Standard HTTP Archive 1.2 for importing into Postman, DevTools, or OWASP ZAP.",
                "HAR 1.2 (.har)", true, false, false, false, true
        ));

        // 6. Fast Triage Spreadsheet (CSV)
        BUILT_IN_PRESETS.put("Triage Metadata Spreadsheet (.csv)", new ExportPreset(
                "Triage Metadata Spreadsheet (.csv)",
                "Lightweight CSV file with sequence numbers, endpoints, status codes, and timings.",
                "CSV Metadata (.csv)", true, false, false, true, true
        ));
    }

    private final Map<String, ExportPreset> customPresets = new LinkedHashMap<>();

    public PresetManager() {
        loadCustomPresets();
    }

    public List<ExportPreset> getAllPresets() {
        List<ExportPreset> all = new ArrayList<>(BUILT_IN_PRESETS.values());
        all.addAll(customPresets.values());
        return all;
    }

    public ExportPreset getPreset(String name) {
        if (BUILT_IN_PRESETS.containsKey(name)) return BUILT_IN_PRESETS.get(name);
        return customPresets.get(name);
    }

    public void saveCustomPreset(ExportPreset preset) {
        if (preset == null || preset.getName() == null || preset.getName().trim().isEmpty()) return;
        preset.setBuiltIn(false);
        customPresets.put(preset.getName().trim(), preset);
        persistCustomPresets();
    }

    public boolean deleteCustomPreset(String name) {
        if (customPresets.containsKey(name)) {
            customPresets.remove(name);
            persistCustomPresets();
            return true;
        }
        return false;
    }

    private void loadCustomPresets() {
        try {
            String json = prefs.get(PREF_KEY_CUSTOM_PRESETS, null);
            if (json != null && !json.trim().isEmpty()) {
                Type type = new TypeToken<List<ExportPreset>>() {}.getType();
                List<ExportPreset> loaded = gson.fromJson(json, type);
                if (loaded != null) {
                    for (ExportPreset p : loaded) {
                        p.setBuiltIn(false);
                        customPresets.put(p.getName(), p);
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void persistCustomPresets() {
        try {
            List<ExportPreset> list = new ArrayList<>(customPresets.values());
            String json = gson.toJson(list);
            prefs.put(PREF_KEY_CUSTOM_PRESETS, json);
        } catch (Exception ignored) {}
    }
}
