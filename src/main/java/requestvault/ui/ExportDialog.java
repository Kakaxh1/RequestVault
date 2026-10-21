package requestvault.ui;

import requestvault.export.*;
import requestvault.model.TrafficRecord;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Multi-format HTTP evidence export dialog supporting customizable Export Presets,
 * cryptographic SHA-256 manifests, credential redaction, and multi-threaded export execution.
 */
public class ExportDialog extends JDialog {

    private final List<TrafficRecord> recordsToExport;
    private final PresetManager presetManager = new PresetManager();

    private final JComboBox<ExportPreset> presetCombo;
    private final JButton savePresetBtn;
    private final JButton deletePresetBtn;

    private final JComboBox<String> formatCombo;
    private final JCheckBox redactSecretsCheck;
    private final JCheckBox generateManifestCheck;
    private final JCheckBox separateFilesCheck;
    private final JTextField pathField;
    private final JButton browseButton;
    private final JButton exportButton;
    private final JButton cancelButton;
    private final JProgressBar progressBar;
    private final JLabel presetDescLabel;

    public ExportDialog(Frame owner, List<TrafficRecord> records) {
        super(owner, "RequestVault - Export HTTP Evidence", true);
        this.recordsToExport = records;

        setLayout(new BorderLayout(10, 10));
        setSize(640, 440);
        setLocationRelativeTo(owner);

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        // Row 0: Header Info
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3;
        JLabel headerLabel = new JLabel(String.format("Exporting %d Selected Traffic Record(s)", records.size()));
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 14f));
        mainPanel.add(headerLabel, gbc);

        // Row 1: Export Preset Selector & Management
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1; gbc.weightx = 0;
        mainPanel.add(new JLabel("Export Preset:"), gbc);

        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        presetCombo = new JComboBox<>();
        refreshPresetCombo();
        mainPanel.add(presetCombo, gbc);

        JPanel presetActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        savePresetBtn = new JButton("Save As...");
        savePresetBtn.setToolTipText("Save current settings as a reusable custom preset");
        deletePresetBtn = new JButton("Delete");
        deletePresetBtn.setToolTipText("Delete selected custom preset");
        presetActions.add(savePresetBtn);
        presetActions.add(deletePresetBtn);

        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0;
        mainPanel.add(presetActions, gbc);

        // Row 2: Preset Description Subtitle
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
        presetDescLabel = new JLabel("");
        presetDescLabel.setFont(new Font("Segoe UI", Font.ITALIC, 11));
        presetDescLabel.setForeground(Color.GRAY);
        mainPanel.add(presetDescLabel, gbc);

        // Row 3: Format Selection
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1; gbc.weightx = 0;
        mainPanel.add(new JLabel("Export Format:"), gbc);

        gbc.gridx = 1; gbc.gridy = 3; gbc.gridwidth = 2; gbc.weightx = 1.0;
        formatCombo = new JComboBox<>(new String[]{
                "HTML Report (.html)",
                "Markdown Report (.md)",
                "JSON (.json)",
                "RAW HTTP Stream (.txt)",
                "HAR 1.2 (.har)",
                "CSV Metadata (.csv)"
        });
        mainPanel.add(formatCombo, gbc);

        // Row 4: Destination File
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1; gbc.weightx = 0;
        mainPanel.add(new JLabel("Destination:"), gbc);

        gbc.gridx = 1; gbc.gridy = 4; gbc.weightx = 1.0;
        pathField = new JTextField(getDefaultFileName("HTML Report (.html)"));
        mainPanel.add(pathField, gbc);

        gbc.gridx = 2; gbc.gridy = 4; gbc.weightx = 0;
        browseButton = new JButton("Browse...");
        mainPanel.add(browseButton, gbc);

        // Row 5: Policy Options
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 3;
        JPanel optsPanel = new JPanel(new GridLayout(3, 1, 4, 4));
        optsPanel.setBorder(BorderFactory.createTitledBorder("Evidence & Redaction Policy"));

        redactSecretsCheck = new JCheckBox("Redact credentials (mask Authorization, Cookies, API Keys, Passwords)", true);
        generateManifestCheck = new JCheckBox("Generate cryptographically verifiable evidence-manifest.json (SHA-256)", true);
        separateFilesCheck = new JCheckBox("Split records into separate files (RAW mode only)", false);

        optsPanel.add(redactSecretsCheck);
        optsPanel.add(generateManifestCheck);
        optsPanel.add(separateFilesCheck);
        mainPanel.add(optsPanel, gbc);

        // Row 6: Progress Bar
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 3;
        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        mainPanel.add(progressBar, gbc);

        add(mainPanel, BorderLayout.CENTER);

        // Bottom Button Bar
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        exportButton = new JButton("Export Evidence");
        exportButton.setFont(exportButton.getFont().deriveFont(Font.BOLD));
        cancelButton = new JButton("Cancel");

        buttonPanel.add(exportButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // Event Listeners
        formatCombo.addActionListener(e -> {
            String selected = (String) formatCombo.getSelectedItem();
            pathField.setText(getDefaultFileName(selected));
        });

        presetCombo.addActionListener(e -> applySelectedPreset());

        savePresetBtn.addActionListener(e -> onSavePresetClicked());
        deletePresetBtn.addActionListener(e -> onDeletePresetClicked());

        browseButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File(pathField.getText()));
            int res = chooser.showSaveDialog(this);
            if (res == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        cancelButton.addActionListener(e -> dispose());
        exportButton.addActionListener(e -> executeExport());

        // Apply initial preset
        if (presetCombo.getItemCount() > 0) {
            presetCombo.setSelectedIndex(0);
        }
    }

    public ExportDialog(Frame owner, List<TrafficRecord> records, ExportPreset initialPreset) {
        this(owner, records);
        if (initialPreset != null) {
            for (int i = 0; i < presetCombo.getItemCount(); i++) {
                ExportPreset p = presetCombo.getItemAt(i);
                if (p.getName().equalsIgnoreCase(initialPreset.getName())) {
                    presetCombo.setSelectedIndex(i);
                    break;
                }
            }
        }
    }

    private void refreshPresetCombo() {
        presetCombo.removeAllItems();
        List<ExportPreset> presets = presetManager.getAllPresets();
        for (ExportPreset p : presets) {
            presetCombo.addItem(p);
        }
    }

    private void applySelectedPreset() {
        ExportPreset preset = (ExportPreset) presetCombo.getSelectedItem();
        if (preset == null) return;

        formatCombo.setSelectedItem(preset.getFormatName());
        redactSecretsCheck.setSelected(preset.isRedactSecrets());
        generateManifestCheck.setSelected(preset.isGenerateManifest());
        separateFilesCheck.setSelected(preset.isSeparateFiles());
        pathField.setText(getDefaultFileName(preset.getFormatName()));
        presetDescLabel.setText(preset.getDescription() != null ? preset.getDescription() : "");
        deletePresetBtn.setEnabled(!preset.isBuiltIn());
    }

    private void onSavePresetClicked() {
        String name = JOptionPane.showInputDialog(this, "Enter a name for this custom export preset:", "Save Custom Preset", JOptionPane.PLAIN_MESSAGE);
        if (name != null && !name.trim().isEmpty()) {
            ExportPreset custom = new ExportPreset(
                    name.trim(),
                    "Custom user export preset",
                    (String) formatCombo.getSelectedItem(),
                    redactSecretsCheck.isSelected(),
                    generateManifestCheck.isSelected(),
                    separateFilesCheck.isSelected(),
                    false,
                    false
            );
            presetManager.saveCustomPreset(custom);
            refreshPresetCombo();
            for (int i = 0; i < presetCombo.getItemCount(); i++) {
                if (presetCombo.getItemAt(i).getName().equalsIgnoreCase(name.trim())) {
                    presetCombo.setSelectedIndex(i);
                    break;
                }
            }
            JOptionPane.showMessageDialog(this, "Custom preset '" + name.trim() + "' saved successfully!", "Preset Saved", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void onDeletePresetClicked() {
        ExportPreset preset = (ExportPreset) presetCombo.getSelectedItem();
        if (preset == null || preset.isBuiltIn()) {
            JOptionPane.showMessageDialog(this, "Built-in presets cannot be deleted.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this, "Delete custom preset '" + preset.getName() + "'?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            presetManager.deleteCustomPreset(preset.getName());
            refreshPresetCombo();
            if (presetCombo.getItemCount() > 0) presetCombo.setSelectedIndex(0);
        }
    }

    private String getDefaultFileName(String format) {
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String ext = ".json";
        if (format.contains(".txt")) ext = ".txt";
        else if (format.contains(".har")) ext = ".har";
        else if (format.contains(".md")) ext = ".md";
        else if (format.contains(".html")) ext = ".html";
        else if (format.contains(".csv")) ext = ".csv";

        return new File(System.getProperty("user.home"), "requestvault_export_" + timestamp + ext).getAbsolutePath();
    }

    private void executeExport() {
        String destPath = pathField.getText().trim();
        if (destPath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please choose a destination file path.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        File destFile = new File(destPath);
        File parentDir = destFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        ExportOptions options = new ExportOptions();
        options.setRedactSecrets(redactSecretsCheck.isSelected());
        options.setGenerateManifest(generateManifestCheck.isSelected());
        options.setSeparateFiles(separateFilesCheck.isSelected());

        String format = (String) formatCombo.getSelectedItem();
        TrafficExporter exporter;
        if (format.contains(".txt")) {
            exporter = new RawExporter();
        } else if (format.contains(".har")) {
            exporter = new HarExporter();
        } else if (format.contains(".md")) {
            exporter = new MarkdownExporter();
        } else if (format.contains(".html")) {
            exporter = new HtmlExporter();
        } else if (format.contains(".csv")) {
            exporter = new CsvExporter();
        } else {
            exporter = new JsonExporter();
        }

        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        exportButton.setEnabled(false);
        cancelButton.setEnabled(false);

        SwingWorker<ExportResult, Void> worker = new SwingWorker<ExportResult, Void>() {
            @Override
            protected ExportResult doInBackground() throws Exception {
                return exporter.export(recordsToExport, options, destFile);
            }

            @Override
            protected void done() {
                progressBar.setVisible(false);
                exportButton.setEnabled(true);
                cancelButton.setEnabled(true);

                try {
                    ExportResult result = get();
                    if (result.isSuccess()) {
                        String msg = String.format("Successfully exported %d record(s) to:\n%s\n\nTotal bytes: %d",
                                result.getRecordCount(),
                                destFile.getAbsolutePath(),
                                result.getTotalBytes());
                        JOptionPane.showMessageDialog(ExportDialog.this, msg, "Export Complete", JOptionPane.INFORMATION_MESSAGE);
                        dispose();
                    } else {
                        JOptionPane.showMessageDialog(ExportDialog.this, "Export failed: " + result.getErrorMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ExportDialog.this, "Export failed: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        worker.execute();
    }
}
