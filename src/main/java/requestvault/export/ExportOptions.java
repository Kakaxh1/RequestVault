package requestvault.export;

import requestvault.security.RedactionEngine;

public class ExportOptions {

    private boolean redactSecrets;
    private boolean generateManifest;
    private boolean separateFiles;
    private final RedactionEngine redactionEngine;

    public ExportOptions() {
        this.redactSecrets = true;
        this.generateManifest = true;
        this.separateFiles = false;
        this.redactionEngine = new RedactionEngine();
    }

    public boolean isRedactSecrets() { return redactSecrets; }
    public void setRedactSecrets(boolean redactSecrets) { this.redactSecrets = redactSecrets; }

    public boolean isGenerateManifest() { return generateManifest; }
    public void setGenerateManifest(boolean generateManifest) { this.generateManifest = generateManifest; }

    public boolean isSeparateFiles() { return separateFiles; }
    public void setSeparateFiles(boolean separateFiles) { this.separateFiles = separateFiles; }

    public RedactionEngine getRedactionEngine() { return redactionEngine; }
}
