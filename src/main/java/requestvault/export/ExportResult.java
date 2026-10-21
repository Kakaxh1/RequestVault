package requestvault.export;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ExportResult {

    private final String outputPath;
    private int exportedCount;
    private int skippedCount;
    private final List<String> warnings = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    private final List<File> generatedFiles = new ArrayList<>();
    private File manifestFile;

    public ExportResult(String outputPath) {
        this.outputPath = outputPath;
    }

    public String getOutputPath() { return outputPath; }
    public int getExportedCount() { return exportedCount; }
    public void setExportedCount(int exportedCount) { this.exportedCount = exportedCount; }
    public int getSkippedCount() { return skippedCount; }
    public void setSkippedCount(int skippedCount) { this.skippedCount = skippedCount; }

    public List<String> getWarnings() { return warnings; }
    public void addWarning(String warning) { this.warnings.add(warning); }

    public List<String> getErrors() { return errors; }
    public void addError(String error) { this.errors.add(error); }

    public List<File> getGeneratedFiles() { return generatedFiles; }
    public void addGeneratedFile(File file) { this.generatedFiles.add(file); }

    public File getManifestFile() { return manifestFile; }
    public void setManifestFile(File manifestFile) { this.manifestFile = manifestFile; }

    public boolean isSuccess() {
        return errors.isEmpty();
    }

    public int getRecordCount() {
        return exportedCount;
    }

    public long getTotalBytes() {
        long total = 0;
        for (File f : generatedFiles) {
            if (f != null && f.exists()) {
                total += f.length();
            }
        }
        return total;
    }

    public String getErrorMessage() {
        return String.join("; ", errors);
    }
}
