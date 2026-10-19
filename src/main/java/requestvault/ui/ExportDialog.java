package requestvault.ui;

import requestvault.export.*;
import requestvault.model.TrafficRecord;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.List;

public class ExportDialog extends JDialog {

    private final List<TrafficRecord> recordsToExport;
    private final JComboBox<String> formatCombo;
    private final JCheckBox redactSecretsCheck;
    private final JCheckBox generateManifestCheck;
    private final JCheckBox separateFilesCheck;
    private final JTextField pathField;
    private final JButton browseButton;
    private final JButton exportButton;
    private final JButton cancelButton;
    private final JProgressBar progressBar;

    public ExportDialog(Frame owner, List<TrafficRecord> records) {
        super(owner, "RequestVault - Export HTTP Evidence", true);
        this.recordsToExport = records;

        setLayout(new BorderLayout(10, 10));
        setSize(560, 360);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Header info
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3;
        JLabel headerLabel = new JLabel(String.format("Exporting %d Selected Traffic Record(s)", records.size()));
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        mainPanel.add(headerLabel, gbc);

        // Format selection
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        mainPanel.add(new JLabel("Export Format:"), gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
        formatCombo = new JComboBox<>(new String[]{"JSON (.json)", "RAW HTTP Stream (.txt)", "HAR 1.2 (.har)", "Markdown Report (.md)", "HTML Report (.html)", "CSV Metadata (.csv)"});
        mainPanel.add(formatCombo, gbc);

        // Destination Path
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        mainPanel.add(new JLabel("Destination File:"), gbc);

        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 1.0;
        pathField = new JTextField(getDefaultFileName("JSON (.json)"));
        mainPanel.add(pathField, gbc);

        gbc.gridx = 2; gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 0;
        browseButton = new JButton("Browse...");
        mainPanel.add(browseButton, gbc);

        formatCombo.addActionListener(e -> {
            String selected = (String) formatCombo.getSelectedItem();
            pathField.setText(getDefaultFileName(selected));
        });

        browseButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File(pathField.getText()));
            int res = chooser.showSaveDialog(this);
            if (res == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        // Security Options
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        JPanel optsPanel = new JPanel(new GridLayout(3, 1, 4, 4));
        optsPanel.setBorder(BorderFactory.createTitledBorder("Evidence & Redaction Policy"));

        redactSecretsCheck = new JCheckBox("Redact credentials (mask Authorization, Cookies, API Keys, Passwords)", true);
        generateManifestCheck = new JCheckBox("Generate cryptographically verifiable evidence-manifest.json (SHA-256)", true);
        separateFilesCheck = new JCheckBox("Split records into separate files (RAW mode only)", false);

        optsPanel.add(redactSecretsCheck);
        optsPanel.add(generateManifestCheck);
        optsPanel.add(separateFilesCheck);
        mainPanel.add(optsPanel, gbc);

        // Progress bar
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        mainPanel.add(progressBar, gbc);

        add(mainPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        exportButton = new JButton("Export Evidence");
        cancelButton = new JButton("Cancel");

        buttonPanel.add(exportButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        cancelButton.addActionListener(e -> dispose());
        exportButton.addActionListener(e -> executeExport());
    }

    private String getDefaultFileName(String format) {
        String base = System.getProperty("user.home") + File.separator + "requestvault_export_";
        long ts = System.currentTimeMillis();
        if (format.startsWith("JSON")) return base + ts + ".json";
        if (format.startsWith("RAW")) return base + ts + ".txt";
        if (format.startsWith("HAR")) return base + ts + ".har";
        if (format.startsWith("Markdown")) return base + ts + ".md";
        if (format.startsWith("HTML")) return base + ts + ".html";
        return base + ts + ".csv";
    }

    private void executeExport() {
        File dest = new File(pathField.getText().trim());
        if (dest.getParentFile() != null && !dest.getParentFile().exists()) {
            dest.getParentFile().mkdirs();
        }

        ExportOptions options = new ExportOptions();
        options.setRedactSecrets(redactSecretsCheck.isSelected());
        options.setGenerateManifest(generateManifestCheck.isSelected());
        options.setSeparateFiles(separateFilesCheck.isSelected());

        String format = (String) formatCombo.getSelectedItem();
        TrafficExporter exporter;
        if (format.startsWith("JSON")) exporter = new JsonExporter();
        else if (format.startsWith("RAW")) exporter = new RawExporter();
        else if (format.startsWith("HAR")) exporter = new HarExporter();
        else if (format.startsWith("Markdown")) exporter = new MarkdownExporter();
        else if (format.startsWith("HTML")) exporter = new HtmlExporter();
        else exporter = new CsvExporter();

        exportButton.setEnabled(false);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);

        SwingWorker<ExportResult, Void> worker = new SwingWorker<ExportResult, Void>() {
            @Override
            protected ExportResult doInBackground() throws Exception {
                return exporter.export(recordsToExport, options, dest);
            }

            @Override
            protected void done() {
                try {
                    ExportResult result = get();
                    String msg = String.format("Export complete!\n\nExported: %d records\nSkipped: %d records\nFile: %s%s",
                            result.getExportedCount(),
                            result.getSkippedCount(),
                            result.getOutputPath(),
                            result.getManifestFile() != null ? "\nManifest: " + result.getManifestFile().getAbsolutePath() : "");
                    JOptionPane.showMessageDialog(ExportDialog.this, msg, "Export Success", JOptionPane.INFORMATION_MESSAGE);
                    dispose();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ExportDialog.this, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    exportButton.setEnabled(true);
                    progressBar.setVisible(false);
                }
            }
        };
        worker.execute();
    }
}
