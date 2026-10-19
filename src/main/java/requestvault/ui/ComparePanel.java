package requestvault.ui;

import requestvault.analysis.ResponseDiff;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class ComparePanel extends JPanel {

    private final TrafficStore store;
    private final JComboBox<String> comboA;
    private final JComboBox<String> comboB;
    private final JLabel statusDiffLabel;
    private final JLabel sizeDiffLabel;
    private final JTextArea headersDiffArea;
    private final JTextArea bodyDiffArea;
    private List<TrafficRecord> currentRecords;

    public ComparePanel(TrafficStore store) {
        this.store = store;
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top control panel
        JPanel topPanel = new JPanel(new GridBagLayout());
        topPanel.setBorder(BorderFactory.createTitledBorder("Select Responses to Compare (A vs B)"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        gbc.gridx = 0; gbc.gridy = 0;
        topPanel.add(new JLabel("Baseline (Response A):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        comboA = new JComboBox<>();
        topPanel.add(comboA, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        topPanel.add(new JLabel("Modified (Response B):"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        comboB = new JComboBox<>();
        topPanel.add(comboB, gbc);

        JButton compareBtn = new JButton("Run Difference Analysis");
        gbc.gridx = 2; gbc.gridy = 0; gbc.gridheight = 2; gbc.weightx = 0;
        topPanel.add(compareBtn, gbc);

        add(topPanel, BorderLayout.NORTH);

        // Center Diff Display
        JPanel diffDisplay = new JPanel(new BorderLayout(6, 6));

        // Summary bar
        boolean isDark = false;
        Color panelBg = UIManager.getColor("Panel.background");
        if (panelBg != null) {
            double lum = (0.299 * panelBg.getRed() + 0.587 * panelBg.getGreen() + 0.114 * panelBg.getBlue()) / 255.0;
            isDark = lum < 0.5;
        }

        JPanel summaryBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        summaryBar.setBackground(isDark ? new Color(30, 33, 38) : new Color(245, 245, 245));
        summaryBar.setBorder(BorderFactory.createLineBorder(isDark ? new Color(50, 55, 62) : Color.LIGHT_GRAY));
        statusDiffLabel = new JLabel("Status Comparison: N/A");
        statusDiffLabel.setFont(statusDiffLabel.getFont().deriveFont(Font.BOLD));
        sizeDiffLabel = new JLabel("Size Difference: N/A");
        summaryBar.add(statusDiffLabel);
        summaryBar.add(sizeDiffLabel);
        diffDisplay.add(summaryBar, BorderLayout.NORTH);

        // Split pane for Headers and Body diffs
        JTabbedPane tabbedPane = new JTabbedPane();

        headersDiffArea = new JTextArea();
        headersDiffArea.setEditable(false);
        headersDiffArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabbedPane.addTab("Header Differences", new JScrollPane(headersDiffArea));

        bodyDiffArea = new JTextArea();
        bodyDiffArea.setEditable(false);
        bodyDiffArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabbedPane.addTab("Body Diff Highlight", new JScrollPane(bodyDiffArea));

        diffDisplay.add(tabbedPane, BorderLayout.CENTER);
        add(diffDisplay, BorderLayout.CENTER);

        compareBtn.addActionListener(e -> runComparison());
        refreshRecordList();
        store.addListener(this::refreshRecordList);
    }

    public void setRecordsToCompare(TrafficRecord a, TrafficRecord b) {
        refreshRecordList();
        if (currentRecords != null) {
            for (int i = 0; i < currentRecords.size(); i++) {
                if (currentRecords.get(i).getRecordId().equals(a.getRecordId())) {
                    comboA.setSelectedIndex(i);
                }
                if (currentRecords.get(i).getRecordId().equals(b.getRecordId())) {
                    comboB.setSelectedIndex(i);
                }
            }
        }
        runComparison();
    }

    private void refreshRecordList() {
        currentRecords = store.getAllRecords();
        comboA.removeAllItems();
        comboB.removeAllItems();

        for (int i = 0; i < currentRecords.size(); i++) {
            TrafficRecord r = currentRecords.get(i);
            String label = String.format("#%d: [%s %d] %s", i + 1, r.getMethod(), r.getStatusCode(), r.getUrl());
            comboA.addItem(label);
            comboB.addItem(label);
        }
        if (currentRecords.size() > 1) {
            comboB.setSelectedIndex(1);
        }
    }

    private void runComparison() {
        int idxA = comboA.getSelectedIndex();
        int idxB = comboB.getSelectedIndex();

        if (idxA < 0 || idxB < 0 || currentRecords == null || idxA >= currentRecords.size() || idxB >= currentRecords.size()) {
            return;
        }

        TrafficRecord a = currentRecords.get(idxA);
        TrafficRecord b = currentRecords.get(idxB);

        ResponseDiff.DiffReport diff = ResponseDiff.compare(a, b);

        // Status
        if (diff.statusMatch) {
            statusDiffLabel.setText(String.format("Status Match: %d == %d", diff.statusA, diff.statusB));
            statusDiffLabel.setForeground(new Color(0, 130, 0));
        } else {
            statusDiffLabel.setText(String.format("STATUS MISMATCH: %d != %d", diff.statusA, diff.statusB));
            statusDiffLabel.setForeground(Color.RED);
        }

        // Size
        sizeDiffLabel.setText(String.format("Size: A=%d B=%d (Diff: %+d bytes)", diff.sizeA, diff.sizeB, diff.sizeDiff));

        // Headers
        StringBuilder hsb = new StringBuilder();
        if (!diff.headersOnlyInA.isEmpty()) {
            hsb.append("--- Headers only in A ---\n");
            for (String h : diff.headersOnlyInA) hsb.append("[-] ").append(h).append("\n");
            hsb.append("\n");
        }
        if (!diff.headersOnlyInB.isEmpty()) {
            hsb.append("--- Headers only in B ---\n");
            for (String h : diff.headersOnlyInB) hsb.append("[+] ").append(h).append("\n");
            hsb.append("\n");
        }
        if (!diff.headerModifications.isEmpty()) {
            hsb.append("--- Modified Headers ---\n");
            for (String h : diff.headerModifications) hsb.append("[~] ").append(h).append("\n");
        }
        if (diff.headersOnlyInA.isEmpty() && diff.headersOnlyInB.isEmpty() && diff.headerModifications.isEmpty()) {
            hsb.append("Headers are identical.");
        }
        headersDiffArea.setText(hsb.toString());

        // Body
        StringBuilder bsb = new StringBuilder();
        if (diff.bodyDiffLines.isEmpty()) {
            bsb.append("Response bodies are identical.");
        } else {
            bsb.append(String.format("Found %d diff line(s):\n\n", diff.bodyDiffLines.size()));
            for (String line : diff.bodyDiffLines) {
                bsb.append(line).append("\n");
            }
        }
        bodyDiffArea.setText(bsb.toString());
    }
}
