package requestvault.ui;

import requestvault.analysis.ResponseDiff;
import requestvault.analysis.ResponseDiff.*;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Interactive Side-by-Side and Unified HTTP Response Diffing Workbench.
 * Highlights status mismatches, header modifications, body line & inline differences,
 * JSONPath field transitions, and security-relevant observations with difference navigation.
 */
public class ComparePanel extends JPanel {

    private final TrafficStore store;

    // Selector controls
    private final JComboBox<String> comboA;
    private final JComboBox<String> comboB;
    private final JButton swapBtn;
    private final JButton compareBtn;

    // Diff Navigation Controls
    private final JButton prevDiffBtn;
    private final JButton nextDiffBtn;
    private final JLabel diffNavLabel;
    private final List<Integer> diffRowIndices = new ArrayList<>();
    private int currentDiffNavIndex = -1;

    // Summary Header Badges
    private final JLabel statusBadge;
    private final JLabel sizeBadge;
    private final JLabel countsBadge;
    private final JPanel securityBanner;
    private final JTextArea securityObservationsArea;

    // Views
    private final JTabbedPane viewTabs;
    private final JTable sideBySideTable;
    private final SideBySideTableModel sideBySideModel;

    private final JTextArea unifiedDiffArea;

    private final JTable jsonDiffTable;
    private final JsonDiffTableModel jsonDiffModel;
    private final JTextField jsonSearchField;

    private final JTable headerDiffTable;
    private final HeaderDiffTableModel headerDiffModel;

    private final JTextArea rawAreaA;
    private final JTextArea rawAreaB;

    private List<TrafficRecord> currentRecords = new ArrayList<>();
    private DiffReport currentReport = null;

    public ComparePanel(TrafficStore store) {
        this.store = store;
        setLayout(new BorderLayout(0, 6));
        setBorder(new EmptyBorder(8, 8, 8, 8));

        boolean dark = isDarkMode();

        // =============================================================
        // 1. TOP CONTROL PANEL (Selectors + Navigators)
        // =============================================================
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.setBorder(BorderFactory.createTitledBorder("Response Diff Configuration"));

        // Row 1: Comboboxes + Swap + Compare
        JPanel selectorsRow = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(3, 4, 3, 4);

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        selectorsRow.add(new JLabel("Baseline (A):"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.45;
        comboA = new JComboBox<>();
        selectorsRow.add(comboA, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        swapBtn = new JButton("⇄ Swap");
        swapBtn.setToolTipText("Swap Response A and Response B");
        selectorsRow.add(swapBtn, gbc);

        gbc.gridx = 3; gbc.weightx = 0;
        selectorsRow.add(new JLabel("Modified (B):"), gbc);
        gbc.gridx = 4; gbc.weightx = 0.45;
        comboB = new JComboBox<>();
        selectorsRow.add(comboB, gbc);

        gbc.gridx = 5; gbc.weightx = 0;
        compareBtn = new JButton("Compare Responses");
        compareBtn.setFont(compareBtn.getFont().deriveFont(Font.BOLD));
        selectorsRow.add(compareBtn, gbc);

        topPanel.add(selectorsRow);

        // Row 2: Diff Navigation & Jump Toolbar
        JPanel navRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        prevDiffBtn = new JButton("◀ Prev Diff");
        nextDiffBtn = new JButton("Next Diff ▶");
        diffNavLabel = new JLabel("Differences: 0 / 0");
        diffNavLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));

        prevDiffBtn.setEnabled(false);
        nextDiffBtn.setEnabled(false);

        navRow.add(new JLabel("Navigation:"));
        navRow.add(prevDiffBtn);
        navRow.add(diffNavLabel);
        navRow.add(nextDiffBtn);
        topPanel.add(navRow);

        // =============================================================
        // 2. COMPARISON SUMMARY BAR & SECURITY OBSERVATIONS
        // =============================================================
        JPanel summaryContainer = new JPanel(new BorderLayout(4, 4));
        summaryContainer.setBorder(new EmptyBorder(4, 0, 4, 0));

        JPanel badgesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        statusBadge = createBadge("Status: N/A", dark ? new Color(50, 55, 62) : new Color(230, 230, 230));
        sizeBadge = createBadge("Size: N/A", dark ? new Color(50, 55, 62) : new Color(230, 230, 230));
        countsBadge = createBadge("Differences: 0", dark ? new Color(50, 55, 62) : new Color(230, 230, 230));

        badgesPanel.add(statusBadge);
        badgesPanel.add(sizeBadge);
        badgesPanel.add(countsBadge);
        summaryContainer.add(badgesPanel, BorderLayout.NORTH);

        // Security Observations Collapsible Panel
        securityBanner = new JPanel(new BorderLayout());
        securityBanner.setBorder(BorderFactory.createTitledBorder("Security-Relevant Observations (Contextual Signals)"));
        securityObservationsArea = new JTextArea(3, 40);
        securityObservationsArea.setEditable(false);
        securityObservationsArea.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        securityObservationsArea.setBackground(dark ? new Color(38, 32, 24) : new Color(255, 251, 235));
        securityObservationsArea.setForeground(dark ? new Color(255, 204, 102) : new Color(146, 64, 14));
        securityBanner.add(new JScrollPane(securityObservationsArea), BorderLayout.CENTER);
        securityBanner.setVisible(false); // only shown when observations exist
        summaryContainer.add(securityBanner, BorderLayout.SOUTH);

        JPanel headerWrapper = new JPanel(new BorderLayout());
        headerWrapper.add(topPanel, BorderLayout.NORTH);
        headerWrapper.add(summaryContainer, BorderLayout.SOUTH);
        add(headerWrapper, BorderLayout.NORTH);

        // =============================================================
        // 3. MAIN WORKBENCH TABS
        // =============================================================
        viewTabs = new JTabbedPane();

        // TAB 1: Side-by-Side Diff Table
        sideBySideModel = new SideBySideTableModel();
        sideBySideTable = new JTable(sideBySideModel);
        sideBySideTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        sideBySideTable.setRowHeight(22);
        sideBySideTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sideBySideTable.setDefaultRenderer(Object.class, new SideBySideCellRenderer(dark));
        sideBySideTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Column widths
        TableColumn colLineA = sideBySideTable.getColumnModel().getColumn(0);
        colLineA.setPreferredWidth(45);
        colLineA.setMaxWidth(60);

        TableColumn colLineB = sideBySideTable.getColumnModel().getColumn(2);
        colLineB.setPreferredWidth(45);
        colLineB.setMaxWidth(60);

        JScrollPane sideBySideScroll = new JScrollPane(sideBySideTable);
        viewTabs.addTab("Side-by-Side Diff", sideBySideScroll);

        // TAB 2: Unified Diff View
        unifiedDiffArea = new JTextArea();
        unifiedDiffArea.setEditable(false);
        unifiedDiffArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        unifiedDiffArea.setBackground(dark ? new Color(22, 27, 34) : new Color(255, 255, 255));
        unifiedDiffArea.setForeground(dark ? new Color(201, 209, 217) : new Color(36, 41, 47));
        viewTabs.addTab("Unified Diff", new JScrollPane(unifiedDiffArea));

        // TAB 3: JSON Path Field Differences
        JPanel jsonTab = new JPanel(new BorderLayout(4, 4));
        JPanel jsonTop = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        jsonSearchField = new JTextField(25);
        jsonTop.add(new JLabel("Filter JSON Path:"));
        jsonTop.add(jsonSearchField);
        jsonTab.add(jsonTop, BorderLayout.NORTH);

        jsonDiffModel = new JsonDiffTableModel();
        jsonDiffTable = new JTable(jsonDiffModel);
        jsonDiffTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        jsonDiffTable.setRowHeight(22);
        jsonDiffTable.setDefaultRenderer(Object.class, new DiffTypeCellRenderer(dark));
        jsonTab.add(new JScrollPane(jsonDiffTable), BorderLayout.CENTER);
        viewTabs.addTab("JSON Path Differences", jsonTab);

        // TAB 4: Headers Comparison Table
        headerDiffModel = new HeaderDiffTableModel();
        headerDiffTable = new JTable(headerDiffModel);
        headerDiffTable.setFont(new Font("Consolas", Font.PLAIN, 12));
        headerDiffTable.setRowHeight(22);
        headerDiffTable.setDefaultRenderer(Object.class, new DiffTypeCellRenderer(dark));
        viewTabs.addTab("Header Differences", new JScrollPane(headerDiffTable));

        // TAB 5: Raw HTTP Wire Comparison
        JPanel rawTab = new JPanel(new GridLayout(1, 2, 8, 0));
        rawAreaA = new JTextArea();
        rawAreaA.setEditable(false);
        rawAreaA.setFont(new Font("Consolas", Font.PLAIN, 12));
        JPanel rawPanelA = new JPanel(new BorderLayout());
        rawPanelA.setBorder(BorderFactory.createTitledBorder("Raw Response A (Wire Format)"));
        rawPanelA.add(new JScrollPane(rawAreaA), BorderLayout.CENTER);

        rawAreaB = new JTextArea();
        rawAreaB.setEditable(false);
        rawAreaB.setFont(new Font("Consolas", Font.PLAIN, 12));
        JPanel rawPanelB = new JPanel(new BorderLayout());
        rawPanelB.setBorder(BorderFactory.createTitledBorder("Raw Response B (Wire Format)"));
        rawPanelB.add(new JScrollPane(rawAreaB), BorderLayout.CENTER);

        rawTab.add(rawPanelA);
        rawTab.add(rawPanelB);
        viewTabs.addTab("Raw Wire Comparison", rawTab);

        add(viewTabs, BorderLayout.CENTER);

        // =============================================================
        // 4. ACTION LISTENERS & LOGIC
        // =============================================================
        compareBtn.addActionListener(e -> runComparisonAsync());

        swapBtn.addActionListener(e -> {
            int a = comboA.getSelectedIndex();
            int b = comboB.getSelectedIndex();
            comboA.setSelectedIndex(b);
            comboB.setSelectedIndex(a);
            runComparisonAsync();
        });

        prevDiffBtn.addActionListener(e -> navigateDiff(-1));
        nextDiffBtn.addActionListener(e -> navigateDiff(1));

        jsonSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterJsonDiffs(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterJsonDiffs(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filterJsonDiffs(); }
        });

        refreshRecordList();
        store.addListener(this::refreshRecordList);
    }

    private JLabel createBadge(String text, Color bg) {
        JLabel label = new JLabel("  " + text + "  ");
        label.setFont(new Font("Segoe UI", Font.BOLD, 12));
        label.setOpaque(true);
        label.setBackground(bg);
        label.setBorder(BorderFactory.createLineBorder(bg.darker(), 1, true));
        return label;
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
        runComparisonAsync();
    }

    private void refreshRecordList() {
        currentRecords = store.getAllRecords();
        int selA = comboA.getSelectedIndex();
        int selB = comboB.getSelectedIndex();

        comboA.removeAllItems();
        comboB.removeAllItems();

        for (int i = 0; i < currentRecords.size(); i++) {
            TrafficRecord r = currentRecords.get(i);
            String item = String.format("#%d [%s %d] %s", r.getSequenceNumber(), r.getMethod(), r.getStatusCode(), r.getUrl());
            comboA.addItem(item);
            comboB.addItem(item);
        }

        if (selA >= 0 && selA < currentRecords.size()) comboA.setSelectedIndex(selA);
        if (selB >= 0 && selB < currentRecords.size()) comboB.setSelectedIndex(selB);
        else if (currentRecords.size() > 1 && comboB.getSelectedIndex() < 0) comboB.setSelectedIndex(1);
    }

    private void runComparisonAsync() {
        int idxA = comboA.getSelectedIndex();
        int idxB = comboB.getSelectedIndex();

        if (idxA < 0 || idxB < 0 || currentRecords == null || idxA >= currentRecords.size() || idxB >= currentRecords.size()) {
            return;
        }

        TrafficRecord a = currentRecords.get(idxA);
        TrafficRecord b = currentRecords.get(idxB);

        compareBtn.setEnabled(false);
        compareBtn.setText("Analyzing...");

        SwingWorker<DiffReport, Void> worker = new SwingWorker<DiffReport, Void>() {
            @Override
            protected DiffReport doInBackground() {
                return ResponseDiff.compare(a, b);
            }

            @Override
            protected void done() {
                try {
                    currentReport = get();
                    displayReport(currentReport, a, b);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(ComparePanel.this, "Error computing diff: " + ex.getMessage(), "Diff Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    compareBtn.setEnabled(true);
                    compareBtn.setText("Compare Responses");
                }
            }
        };
        worker.execute();
    }

    private void displayReport(DiffReport report, TrafficRecord a, TrafficRecord b) {
        boolean dark = isDarkMode();

        // 1. Status Badge
        if (!report.hasResponseA || !report.hasResponseB) {
            statusBadge.setText("Status: Incomplete Pair");
            statusBadge.setBackground(dark ? new Color(70, 50, 50) : new Color(254, 226, 226));
            statusBadge.setForeground(dark ? new Color(252, 165, 165) : new Color(185, 28, 28));
        } else if (report.statusMatch) {
            statusBadge.setText(String.format("Status Match: %d %s", report.statusA, report.statusReasonA));
            statusBadge.setBackground(dark ? new Color(20, 60, 30) : new Color(220, 252, 231));
            statusBadge.setForeground(dark ? new Color(134, 239, 172) : new Color(21, 128, 61));
        } else {
            statusBadge.setText(String.format("Status Mismatch: %d (%s) vs %d (%s)", report.statusA, report.statusReasonA, report.statusB, report.statusReasonB));
            statusBadge.setBackground(dark ? new Color(80, 25, 25) : new Color(254, 226, 226));
            statusBadge.setForeground(dark ? new Color(248, 113, 113) : new Color(185, 28, 28));
        }

        // 2. Size Badge
        String sizeDeltaStr = String.format("%+d B", report.sizeDiff);
        sizeBadge.setText(String.format("Size: A=%d B | B=%d B (Δ %s)", report.sizeA, report.sizeB, sizeDeltaStr));
        if (Math.abs(report.sizeDiff) > 0) {
            sizeBadge.setBackground(dark ? new Color(60, 50, 20) : new Color(254, 240, 138));
            sizeBadge.setForeground(dark ? new Color(253, 224, 71) : new Color(161, 98, 7));
        } else {
            sizeBadge.setBackground(dark ? new Color(30, 40, 50) : new Color(240, 240, 240));
            sizeBadge.setForeground(dark ? new Color(200, 200, 200) : new Color(80, 80, 80));
        }

        // 3. Difference Counts Badge
        countsBadge.setText(String.format("Diffs: %d line(s) [%d mod, %d add, %d rem] | %d JSON change(s)",
                report.totalDiffRows, report.modifiedLinesCount, report.addedLinesCount, report.removedLinesCount, report.jsonDiffs.size()));

        // 4. Security Observations
        if (!report.securityObservations.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (SecurityObservation obs : report.securityObservations) {
                sb.append("• [").append(obs.getCategory()).append("] ").append(obs.getDescription()).append("\n");
            }
            securityObservationsArea.setText(sb.toString().trim());
            securityBanner.setVisible(true);
        } else {
            securityObservationsArea.setText("");
            securityBanner.setVisible(false);
        }

        // 5. Populate Side-by-Side Table Model & Collect Diff Row Indices
        sideBySideModel.setRows(report.bodyDiffRows);
        diffRowIndices.clear();
        for (int i = 0; i < report.bodyDiffRows.size(); i++) {
            if (report.bodyDiffRows.get(i).isDifferent()) {
                diffRowIndices.add(i);
            }
        }

        currentDiffNavIndex = -1;
        if (!diffRowIndices.isEmpty()) {
            prevDiffBtn.setEnabled(true);
            nextDiffBtn.setEnabled(true);
            diffNavLabel.setText(String.format("Differences: 0 / %d", diffRowIndices.size()));
        } else {
            prevDiffBtn.setEnabled(false);
            nextDiffBtn.setEnabled(false);
            diffNavLabel.setText("Differences: 0 / 0");
        }

        // 6. Populate Unified Diff View
        StringBuilder usb = new StringBuilder();
        if (report.unifiedDiffLines.isEmpty()) {
            usb.append("Response bodies are identical.\n");
        } else {
            for (String uline : report.unifiedDiffLines) {
                usb.append(uline).append("\n");
            }
        }
        if (report.isTruncated) {
            usb.append("\n[Note: Diff view was truncated at 10,000 lines for responsiveness]\n");
        }
        unifiedDiffArea.setText(usb.toString());
        unifiedDiffArea.setCaretPosition(0);

        // 7. Populate JSON & Headers Models
        jsonDiffModel.setDiffs(report.jsonDiffs);
        headerDiffModel.setDiffs(report.headerDiffs);

        // 8. Populate Raw HTTP Wire Area
        rawAreaA.setText(a.hasResponse() ? new String(a.getResponseBytes(), java.nio.charset.StandardCharsets.UTF_8) : "[No Response Recorded]");
        rawAreaA.setCaretPosition(0);
        rawAreaB.setText(b.hasResponse() ? new String(b.getResponseBytes(), java.nio.charset.StandardCharsets.UTF_8) : "[No Response Recorded]");
        rawAreaB.setCaretPosition(0);

        revalidate();
        repaint();
    }

    private void navigateDiff(int direction) {
        if (diffRowIndices.isEmpty()) return;

        currentDiffNavIndex += direction;
        if (currentDiffNavIndex < 0) currentDiffNavIndex = diffRowIndices.size() - 1;
        if (currentDiffNavIndex >= diffRowIndices.size()) currentDiffNavIndex = 0;

        int tableRow = diffRowIndices.get(currentDiffNavIndex);
        diffNavLabel.setText(String.format("Difference %d / %d", currentDiffNavIndex + 1, diffRowIndices.size()));

        sideBySideTable.setRowSelectionInterval(tableRow, tableRow);
        sideBySideTable.scrollRectToVisible(sideBySideTable.getCellRect(tableRow, 1, true));
    }

    private void filterJsonDiffs() {
        if (currentReport == null) return;
        String query = jsonSearchField.getText().trim().toLowerCase();
        if (query.isEmpty()) {
            jsonDiffModel.setDiffs(currentReport.jsonDiffs);
        } else {
            List<JsonFieldDiff> filtered = new ArrayList<>();
            for (JsonFieldDiff d : currentReport.jsonDiffs) {
                if (d.getPath().toLowerCase().contains(query) || d.getValueA().toLowerCase().contains(query) || d.getValueB().toLowerCase().contains(query)) {
                    filtered.add(d);
                }
            }
            jsonDiffModel.setDiffs(filtered);
        }
    }

    private boolean isDarkMode() {
        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) return false;
        double lum = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
        return lum < 0.5;
    }

    // =========================================================================
    // TABLE MODELS & RENDERERS
    // =========================================================================

    private static class SideBySideTableModel extends AbstractTableModel {
        private final String[] columns = {"# A", "Response A (Baseline)", "# B", "Response B (Modified)"};
        private List<DiffRow> rows = new ArrayList<>();

        public void setRows(List<DiffRow> rows) {
            this.rows = rows != null ? rows : new ArrayList<>();
            fireTableDataChanged();
        }

        public DiffRow getRow(int row) {
            if (row >= 0 && row < rows.size()) return rows.get(row);
            return null;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= rows.size()) return null;
            DiffRow row = rows.get(rowIndex);
            switch (columnIndex) {
                case 0: return row.getLineNumA() > 0 ? String.valueOf(row.getLineNumA()) : "";
                case 1: return row.getTextA();
                case 2: return row.getLineNumB() > 0 ? String.valueOf(row.getLineNumB()) : "";
                case 3: return row.getTextB();
                default: return null;
            }
        }
    }

    private static class SideBySideCellRenderer extends DefaultTableCellRenderer {
        private final boolean dark;

        public SideBySideCellRenderer(boolean dark) {
            this.dark = dark;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            SideBySideTableModel model = (SideBySideTableModel) table.getModel();
            DiffRow diffRow = model.getRow(row);

            if (diffRow != null) {
                // Default colors
                Color bgUnchanged = dark ? new Color(22, 27, 34) : Color.WHITE;
                Color fgUnchanged = dark ? new Color(201, 209, 217) : new Color(36, 41, 47);

                // Colors for Added, Removed, Modified
                Color bgAdded = dark ? new Color(24, 58, 36) : new Color(220, 252, 231);
                Color fgAdded = dark ? new Color(134, 239, 172) : new Color(21, 128, 61);

                Color bgRemoved = dark ? new Color(68, 25, 28) : new Color(254, 226, 226);
                Color fgRemoved = dark ? new Color(248, 113, 113) : new Color(185, 28, 28);

                Color bgModified = dark ? new Color(64, 52, 20) : new Color(254, 240, 138);
                Color fgModified = dark ? new Color(253, 224, 71) : new Color(161, 98, 7);

                if (!isSelected) {
                    if (diffRow.getType() == DiffType.ADDED) {
                        c.setBackground(bgAdded);
                        c.setForeground(fgAdded);
                    } else if (diffRow.getType() == DiffType.REMOVED) {
                        c.setBackground(bgRemoved);
                        c.setForeground(fgRemoved);
                    } else if (diffRow.getType() == DiffType.MODIFIED) {
                        c.setBackground(bgModified);
                        c.setForeground(fgModified);
                    } else {
                        c.setBackground(bgUnchanged);
                        c.setForeground(fgUnchanged);
                    }
                }

                // Format line number columns with subtle muted styling
                if (column == 0 || column == 2) {
                    setHorizontalAlignment(SwingConstants.RIGHT);
                    c.setForeground(dark ? new Color(110, 118, 129) : new Color(140, 149, 159));
                } else {
                    setHorizontalAlignment(SwingConstants.LEFT);
                }

                // If modified and cell has inline diff, show tool tip
                if (diffRow.getType() == DiffType.MODIFIED && diffRow.getInlineDiff() != null) {
                    setToolTipText("Exact Change: " + diffRow.getInlineDiff());
                } else {
                    setToolTipText(null);
                }
            }
            return c;
        }
    }

    private static class JsonDiffTableModel extends AbstractTableModel {
        private final String[] columns = {"Change Type", "JSON Path", "Value in A (Baseline)", "Value in B (Modified)", "Security Signal"};
        private List<JsonFieldDiff> diffs = new ArrayList<>();

        public void setDiffs(List<JsonFieldDiff> diffs) {
            this.diffs = diffs != null ? diffs : new ArrayList<>();
            fireTableDataChanged();
        }

        public JsonFieldDiff getDiff(int r) { return (r >= 0 && r < diffs.size()) ? diffs.get(r) : null; }

        @Override public int getRowCount() { return diffs.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= diffs.size()) return null;
            JsonFieldDiff d = diffs.get(rowIndex);
            switch (columnIndex) {
                case 0: return d.getType().name();
                case 1: return d.getPath();
                case 2: return d.getValueA();
                case 3: return d.getValueB();
                case 4: return d.isSecurityRelevant() ? "⚠️ Context Signal" : "";
                default: return null;
            }
        }
    }

    private static class HeaderDiffTableModel extends AbstractTableModel {
        private final String[] columns = {"Change Type", "Header Name", "Value in A (Baseline)", "Value in B (Modified)", "Security Signal"};
        private List<HeaderDiff> diffs = new ArrayList<>();

        public void setDiffs(List<HeaderDiff> diffs) {
            this.diffs = diffs != null ? diffs : new ArrayList<>();
            fireTableDataChanged();
        }

        public HeaderDiff getDiff(int r) { return (r >= 0 && r < diffs.size()) ? diffs.get(r) : null; }

        @Override public int getRowCount() { return diffs.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= diffs.size()) return null;
            HeaderDiff d = diffs.get(rowIndex);
            switch (columnIndex) {
                case 0: return d.getType().name();
                case 1: return d.getName();
                case 2: return d.getValueA();
                case 3: return d.getValueB();
                case 4: return d.isSecurityRelevant() ? "⚠️ Sensitive Header" : "";
                default: return null;
            }
        }
    }

    private static class DiffTypeCellRenderer extends DefaultTableCellRenderer {
        private final boolean dark;

        public DiffTypeCellRenderer(boolean dark) { this.dark = dark; }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String type = String.valueOf(table.getValueAt(row, 0));

            if (!isSelected) {
                if ("ADDED".equalsIgnoreCase(type)) {
                    c.setForeground(dark ? new Color(134, 239, 172) : new Color(21, 128, 61));
                } else if ("REMOVED".equalsIgnoreCase(type)) {
                    c.setForeground(dark ? new Color(248, 113, 113) : new Color(185, 28, 28));
                } else if ("MODIFIED".equalsIgnoreCase(type)) {
                    c.setForeground(dark ? new Color(253, 224, 71) : new Color(161, 98, 7));
                } else {
                    c.setForeground(dark ? new Color(180, 185, 190) : new Color(70, 75, 80));
                }
            }
            return c;
        }
    }
}
