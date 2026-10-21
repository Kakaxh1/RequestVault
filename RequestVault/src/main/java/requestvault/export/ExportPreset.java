package requestvault.export;

import java.io.Serializable;

/**
 * Reusable configuration preset for exporting evidence.
 * Supports TXT (RAW), JSON, CSV, HTML, Markdown, and HAR formats with pre-set security & formatting policies.
 */
public class ExportPreset implements Serializable {
    private static final long serialVersionUID = 1L;

    private String name;
    private String description;
    private String formatName; // "HTML Report (.html)", "Markdown Report (.md)", "JSON (.json)", "RAW HTTP Stream (.txt)", "HAR 1.2 (.har)", "CSV Metadata (.csv)"
    private boolean redactSecrets;
    private boolean generateManifest;
    private boolean separateFiles;
    private boolean excludeStatic;
    private boolean isBuiltIn;

    public ExportPreset() {
        this("Default", "Standard export", "JSON (.json)", true, true, false, false, false);
    }

    public ExportPreset(String name, String description, String formatName, boolean redactSecrets,
                        boolean generateManifest, boolean separateFiles, boolean excludeStatic, boolean isBuiltIn) {
        this.name = name;
        this.description = description;
        this.formatName = formatName;
        this.redactSecrets = redactSecrets;
        this.generateManifest = generateManifest;
        this.separateFiles = separateFiles;
        this.excludeStatic = excludeStatic;
        this.isBuiltIn = isBuiltIn;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getFormatName() { return formatName; }
    public void setFormatName(String formatName) { this.formatName = formatName; }

    public boolean isRedactSecrets() { return redactSecrets; }
    public void setRedactSecrets(boolean redactSecrets) { this.redactSecrets = redactSecrets; }

    public boolean isGenerateManifest() { return generateManifest; }
    public void setGenerateManifest(boolean generateManifest) { this.generateManifest = generateManifest; }

    public boolean isSeparateFiles() { return separateFiles; }
    public void setSeparateFiles(boolean separateFiles) { this.separateFiles = separateFiles; }

    public boolean isExcludeStatic() { return excludeStatic; }
    public void setExcludeStatic(boolean excludeStatic) { this.excludeStatic = excludeStatic; }

    public boolean isBuiltIn() { return isBuiltIn; }
    public void setBuiltIn(boolean builtIn) { isBuiltIn = builtIn; }

    @Override
    public String toString() {
        return name + (isBuiltIn ? " [Built-in]" : " [Custom]");
    }
}
