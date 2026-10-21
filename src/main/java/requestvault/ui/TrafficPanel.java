package requestvault.ui;

import burp.api.montoya.MontoyaApi;
import requestvault.analysis.TrafficFilter;
import requestvault.capture.LiveProxyCaptureHandler;
import requestvault.capture.ProxyHistoryImporter;
import requestvault.export.ClipboardHelper;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.*;
import java.util.List;

import requestvault.analysis.TrafficFilter.MimeCategory;
import requestvault.analysis.TrafficFilter.SearchScope;
import requestvault.analysis.TrafficFilter.TimeRangeMode;
import requestvault.export.*;
import java.text.SimpleDateFormat;

public class TrafficPanel extends JPanel {

    private final MontoyaApi api;
    private final TrafficStore store;
    private final ComparePanel comparePanel;
    private final LiveProxyCaptureHandler liveHandler;

    // Selection Tracking
    private final Set<String> selectedRecordIds = Collections.synchronizedSet(new HashSet<>());

    // Domain Tree Panel (Left)
    private final DomainTreePanel domainTreePanel;

    // Scope Radio / Checkbox
    private final JRadioButton scopeBothRadio;
    private final JRadioButton scopeReqOnlyRadio;
    private final JRadioButton scopeRespOnlyRadio;
    private final JCheckBox inScopeCheck;

    // HTTP Method Checkboxes
    private final Map<String, JCheckBox> methodCheckboxes = new LinkedHashMap<>();

    // Smart Filters & Search Fields
    private final JTextField searchField;
    private final JComboBox<SearchScope> searchScopeCombo;
    private final JCheckBox caseSensitiveCheck;
    private final JCheckBox regexModeCheck;
    private final JCheckBox invertMatchCheck;

    private final JComboBox<String> statusCategoryCombo;
    private final JTextField statusCodesField;
    private final JComboBox<MimeCategory> mimeCategoryCombo;
    private final JTextField contentTypeField;
    private final JComboBox<TimeRangeMode> timeRangeCombo;
    private final JCheckBox authEndpointsCheck;
    private final JTextField apiPathField;

    private final JComboBox<String> selectionFilterCombo;
    private final JTextField fromNumField;
    private final JTextField toNumField;
    private Integer activeRangeFrom = null;
    private Integer activeRangeTo = null;

    private final PresetManager presetManager = new PresetManager();

    // Body Handling Checkboxes
    private final JCheckBox excludeStaticCheck;
    private final JCheckBox removeDuplicatesCheck;
    private final JTextField maxBodySizeField;

    // Action Buttons
    private final JToggleButton liveCaptureBtn;

    // Center Display (Table + Preview Tabs)
    private final TrafficTableModel tableModel = new TrafficTableModel();
    private final JTable trafficTable;
    private List<TrafficRecord> displayedRecords = new ArrayList<>();
    private final JTextArea previewArea;

    // Inspector
    private final JTextArea reqArea;
    private final JTextArea respArea;
    private final JTextArea metadataArea;

    // Bottom Stats Bar
    private final JLabel statsLabel;

    public TrafficPanel(MontoyaApi api, TrafficStore store, ComparePanel comparePanel, LiveProxyCaptureHandler liveHandler) {
        this.api = api;
        this.store = store;
        this.comparePanel = comparePanel;
        this.liveHandler = liveHandler;

        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        boolean dark = isDarkMode();

        // -------------------------------------------------------------
        // 1. TOP SECTION (HORIZONTAL SPLIT: DOMAINS LEFT, CONTROLS RIGHT)
        // -------------------------------------------------------------

        // Left Panel: Domain / Subdomain Filter
        domainTreePanel = new DomainTreePanel(store, selectedHosts -> applyFilters());
        domainTreePanel.setPreferredSize(new Dimension(280, 240));

        // Right Panel: Export Controls & Filters
        JPanel exportControlsPanel = new JPanel();
        exportControlsPanel.setLayout(new BoxLayout(exportControlsPanel, BoxLayout.Y_AXIS));
        exportControlsPanel.setBorder(BorderFactory.createTitledBorder("Export Controls"));

        // Scope Subpanel
        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 2));
        scopePanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Scope"));
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeBothRadio = new JRadioButton("Requests + Responses (default)", true);
        scopeReqOnlyRadio = new JRadioButton("Requests only");
        scopeRespOnlyRadio = new JRadioButton("Responses only");
        inScopeCheck = new JCheckBox("In-scope only (Burp Target scope)", false);

        scopeGroup.add(scopeBothRadio);
        scopeGroup.add(scopeReqOnlyRadio);
        scopeGroup.add(scopeRespOnlyRadio);

        scopePanel.add(scopeBothRadio);
        scopePanel.add(scopeReqOnlyRadio);
        scopePanel.add(scopeRespOnlyRadio);
        scopePanel.add(inScopeCheck);
        exportControlsPanel.add(scopePanel);

        // HTTP Methods Subpanel
        JPanel methodsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        methodsPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "HTTP Methods"));
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "OTHER"};
        for (String m : methods) {
            JCheckBox cb = new JCheckBox(m, true);
            cb.addActionListener(e -> applyFilters());
            methodCheckboxes.put(m, cb);
            methodsPanel.add(cb);
        }
        exportControlsPanel.add(methodsPanel);

        // Filters Subpanel
        JPanel filtersGrid = new JPanel(new GridBagLayout());
        filtersGrid.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Filters & Search"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(2, 4, 2, 4);

        // --- ROW 0: ADVANCED TRAFFIC SEARCH ---
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Search:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        searchField = new JTextField(12);
        filtersGrid.add(searchField, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Scope:"), gbc);

        gbc.gridx = 3; gbc.weightx = 1.0;
        JPanel searchOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        searchScopeCombo = new JComboBox<>(SearchScope.values());
        caseSensitiveCheck = new JCheckBox("Case");
        caseSensitiveCheck.setToolTipText("Case-sensitive search");
        regexModeCheck = new JCheckBox("Regex");
        regexModeCheck.setToolTipText("Regular expression search");
        invertMatchCheck = new JCheckBox("Invert");
        invertMatchCheck.setToolTipText("Invert matching results (NOT)");
        searchOptionsPanel.add(searchScopeCombo);
        searchOptionsPanel.add(caseSensitiveCheck);
        searchOptionsPanel.add(regexModeCheck);
        searchOptionsPanel.add(invertMatchCheck);
        filtersGrid.add(searchOptionsPanel, gbc);

        // --- ROW 1: SMART STATUS & CONTENT-TYPE (MIME) ---
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Status:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel statusBox = new JPanel(new BorderLayout(4, 0));
        statusCategoryCombo = new JComboBox<>(new String[]{
                "All Statuses",
                "2xx Success",
                "3xx Redirection",
                "4xx Client Error",
                "5xx Server Error",
                "Auth Failures (401, 403)"
        });
        statusCodesField = new JTextField(6);
        statusCodesField.setToolTipText("Custom status codes/ranges e.g. 200, 302, 401-404, 5xx");
        statusBox.add(statusCategoryCombo, BorderLayout.CENTER);
        statusBox.add(statusCodesField, BorderLayout.EAST);
        filtersGrid.add(statusBox, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        filtersGrid.add(new JLabel("MIME Type:"), gbc);

        gbc.gridx = 3; gbc.weightx = 1.0;
        JPanel mimeBox = new JPanel(new BorderLayout(4, 0));
        mimeCategoryCombo = new JComboBox<>(MimeCategory.values());
        contentTypeField = new JTextField(8);
        contentTypeField.setToolTipText("Custom MIME substring e.g. application/json, text/xml");
        mimeBox.add(mimeCategoryCombo, BorderLayout.CENTER);
        mimeBox.add(contentTypeField, BorderLayout.EAST);
        filtersGrid.add(mimeBox, gbc);

        // --- ROW 2: TIME RANGE & API PATH & AUTH ENDPOINTS ---
        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Time:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        timeRangeCombo = new JComboBox<>(TimeRangeMode.values());
        filtersGrid.add(timeRangeCombo, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Path / Auth:"), gbc);

        gbc.gridx = 3; gbc.weightx = 1.0;
        JPanel pathAuthBox = new JPanel(new BorderLayout(6, 0));
        apiPathField = new JTextField(10);
        apiPathField.setToolTipText("Filter by path prefix or substring e.g. /api/v1");
        authEndpointsCheck = new JCheckBox("Auth Endpoints Only");
        authEndpointsCheck.setToolTipText("Match authentication endpoints (/login, /token, /oauth, etc.) or auth headers");
        pathAuthBox.add(apiPathField, BorderLayout.CENTER);
        pathAuthBox.add(authEndpointsCheck, BorderLayout.EAST);
        filtersGrid.add(pathAuthBox, gbc);

        // --- ROW 3: RANGE & SELECTION MODE ---
        gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Range #:"), gbc);

        gbc.gridx = 1; gbc.weightx = 1.0;
        JPanel rangeBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        fromNumField = new JTextField(4);
        toNumField = new JTextField(4);
        JButton selectRangeBtn = new JButton("Select");
        selectRangeBtn.addActionListener(e -> onSelectRangeClicked());
        JButton filterRangeBtn = new JButton("Filter");
        filterRangeBtn.addActionListener(e -> onFilterRangeClicked());
        JButton resetRangeBtn = new JButton("Reset");
        resetRangeBtn.addActionListener(e -> {
            activeRangeFrom = null;
            activeRangeTo = null;
            fromNumField.setText("");
            toNumField.setText("");
            applyFilters();
        });
        rangeBox.add(fromNumField);
        rangeBox.add(new JLabel("-"));
        rangeBox.add(toNumField);
        rangeBox.add(selectRangeBtn);
        rangeBox.add(filterRangeBtn);
        rangeBox.add(resetRangeBtn);
        filtersGrid.add(rangeBox, gbc);

        gbc.gridx = 2; gbc.weightx = 0;
        filtersGrid.add(new JLabel("Selection:"), gbc);

        gbc.gridx = 3; gbc.weightx = 1.0;
        selectionFilterCombo = new JComboBox<>(new String[]{"All Records", "Selected Only", "Unselected Only"});
        selectionFilterCombo.addActionListener(e -> applyFilters());
        filtersGrid.add(selectionFilterCombo, gbc);

        exportControlsPanel.add(filtersGrid);

        // Body Handling Subpanel
        JPanel bodyHandlingPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        bodyHandlingPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Body Handling"));
        excludeStaticCheck = new JCheckBox("Exclude static assets (.js, .css, images...)", false);
        excludeStaticCheck.addActionListener(e -> applyFilters());
        removeDuplicatesCheck = new JCheckBox("Remove duplicate URLs (keep latest)", false);
        removeDuplicatesCheck.addActionListener(e -> applyFilters());
        maxBodySizeField = new JTextField("5000", 5);

        bodyHandlingPanel.add(excludeStaticCheck);
        bodyHandlingPanel.add(removeDuplicatesCheck);
        bodyHandlingPanel.add(new JLabel("Max body size (KB):"));
        bodyHandlingPanel.add(maxBodySizeField);
        exportControlsPanel.add(bodyHandlingPanel);

        // Actions & Copy Toolbar
        JPanel actionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        JButton exportBtn = new JButton("Export Evidence...");
        exportBtn.setFont(exportBtn.getFont().deriveFont(Font.BOLD));
        exportBtn.addActionListener(e -> onExportClicked());

        JButton presetBtn = new JButton("Export Preset ▼");
        presetBtn.setToolTipText("Quickly export with a built-in or custom preset");
        presetBtn.addActionListener(e -> showPresetMenu(presetBtn));

        JButton copyBtn = new JButton("Copy as... ▼");
        copyBtn.setFont(copyBtn.getFont().deriveFont(Font.BOLD));
        JPopupMenu copyMenu = new JPopupMenu();

        JMenuItem copyJsonItem = new JMenuItem("Copy as JSON");
        copyJsonItem.addActionListener(e -> copySelected("JSON"));
        copyMenu.add(copyJsonItem);

        JMenuItem copyCsvItem = new JMenuItem("Copy as CSV");
        copyCsvItem.addActionListener(e -> copySelected("CSV"));
        copyMenu.add(copyCsvItem);

        JMenuItem copyHtmlItem = new JMenuItem("Copy as HTML");
        copyHtmlItem.addActionListener(e -> copySelected("HTML"));
        copyMenu.add(copyHtmlItem);

        JMenuItem copyMdItem = new JMenuItem("Copy as Markdown");
        copyMdItem.addActionListener(e -> copySelected("MARKDOWN"));
        copyMenu.add(copyMdItem);

        copyBtn.addActionListener(e -> copyMenu.show(copyBtn, 0, copyBtn.getHeight()));

        // Live Capture Toggle Button
        liveCaptureBtn = new JToggleButton();
        liveCaptureBtn.setSelected(liveHandler != null && liveHandler.isEnabled());
        liveCaptureBtn.setFocusPainted(false);
        updateLiveCaptureButtonStyle();
        liveCaptureBtn.addActionListener(e -> {
            boolean active = liveCaptureBtn.isSelected();
            if (liveHandler != null) {
                liveHandler.setEnabled(active);
            }
            updateLiveCaptureButtonStyle();
        });

        // Sync Proxy History Button
        JButton syncHistoryBtn = new JButton("📥 Import History");
        syncHistoryBtn.setToolTipText("Load all existing requests and responses from Burp's Proxy HTTP History");
        syncHistoryBtn.addActionListener(e -> {
            syncHistoryBtn.setEnabled(false);
            syncHistoryBtn.setText("Importing...");
            ProxyHistoryImporter.importHistoryAsync(api, store, inScopeCheck.isSelected(), count -> {
                syncHistoryBtn.setEnabled(true);
                syncHistoryBtn.setText("📥 Import History");
                domainTreePanel.refreshDomains();
                JOptionPane.showMessageDialog(this,
                        String.format("Loaded %d record(s) from Proxy HTTP History.", count),
                        "History Import Complete",
                        JOptionPane.INFORMATION_MESSAGE);
            });
        });

        JButton selectMatchingBtn = new JButton("Select Matching");
        selectMatchingBtn.addActionListener(e -> {
            for (TrafficRecord r : displayedRecords) {
                selectedRecordIds.add(r.getRecordId());
            }
            tableModel.fireTableDataChanged();
            updateStatsBar();
        });

        JButton compareBtn = new JButton("Compare (2)");
        compareBtn.addActionListener(e -> onCompareClicked());

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Clear all captured records in RequestVault?", "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                store.clear();
                selectedRecordIds.clear();
                domainTreePanel.refreshDomains();
            }
        });

        actionsBar.add(exportBtn);
        actionsBar.add(presetBtn);
        actionsBar.add(copyBtn);
        actionsBar.add(new JSeparator(SwingConstants.VERTICAL));
        actionsBar.add(liveCaptureBtn);
        actionsBar.add(syncHistoryBtn);
        actionsBar.add(new JSeparator(SwingConstants.VERTICAL));
        actionsBar.add(selectMatchingBtn);
        actionsBar.add(compareBtn);
        actionsBar.add(clearBtn);

        exportControlsPanel.add(actionsBar);

        // Top Horizontal SplitPane (Left: Domains, Right: Export Controls)
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, domainTreePanel, exportControlsPanel);
        topSplit.setDividerLocation(300);
        topSplit.setResizeWeight(0.3);

        // -------------------------------------------------------------
        // 2. CENTER SECTION: TABS (TRAFFIC TABLE vs PREVIEW STREAM)
        // -------------------------------------------------------------
        JTabbedPane centerTabs = new JTabbedPane();

        // TAB 1: Traffic Table & Inspector
        trafficTable = new JTable(tableModel);
        trafficTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        trafficTable.setAutoCreateRowSorter(true);

        TableColumn selectCol = trafficTable.getColumnModel().getColumn(0);
        selectCol.setPreferredWidth(45);
        selectCol.setMaxWidth(55);

        TableColumn numCol = trafficTable.getColumnModel().getColumn(1);
        numCol.setPreferredWidth(45);
        numCol.setMaxWidth(65);

        // Right-click context menu for table
        JPopupMenu tableContextMenu = new JPopupMenu();
        JMenuItem tCopyJson = new JMenuItem("Copy as JSON");
        tCopyJson.addActionListener(e -> copySelected("JSON"));
        JMenuItem tCopyCsv = new JMenuItem("Copy as CSV");
        tCopyCsv.addActionListener(e -> copySelected("CSV"));
        JMenuItem tCopyHtml = new JMenuItem("Copy as HTML");
        tCopyHtml.addActionListener(e -> copySelected("HTML"));
        JMenuItem tCopyMd = new JMenuItem("Copy as Markdown");
        tCopyMd.addActionListener(e -> copySelected("MARKDOWN"));

        tableContextMenu.add(tCopyJson);
        tableContextMenu.add(tCopyCsv);
        tableContextMenu.add(tCopyHtml);
        tableContextMenu.add(tCopyMd);
        trafficTable.setComponentPopupMenu(tableContextMenu);

        JScrollPane tableScroll = new JScrollPane(trafficTable);
        tableScroll.setPreferredSize(new Dimension(800, 200));

        JTabbedPane inspectorTabs = new JTabbedPane();
        reqArea = createTextArea();
        respArea = createTextArea();
        metadataArea = createTextArea();
        inspectorTabs.addTab("Request", new JScrollPane(reqArea));
        inspectorTabs.addTab("Response", new JScrollPane(respArea));
        inspectorTabs.addTab("Metadata & Integrity", new JScrollPane(metadataArea));

        JSplitPane tableSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, inspectorTabs);
        tableSplit.setResizeWeight(0.5);
        centerTabs.addTab("Traffic Table", tableSplit);

        // TAB 2: Preview (Raw Flow Stream matching reference image)
        previewArea = createTextArea();
        JScrollPane previewScroll = new JScrollPane(previewArea);
        centerTabs.addTab("Preview (first 5 matching entries)", previewScroll);

        // Main Vertical SplitPane: Top Controls / Center Tabs
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, centerTabs);
        mainSplit.setDividerLocation(270);
        mainSplit.setResizeWeight(0.4);
        add(mainSplit, BorderLayout.CENTER);

        // -------------------------------------------------------------
        // 3. BOTTOM STATUS BAR: STATISTICS & FOOTER
        // -------------------------------------------------------------
        JPanel bottomStatsBar = new JPanel(new BorderLayout());
        bottomStatsBar.setBackground(dark ? new Color(28, 31, 36) : new Color(245, 247, 250));
        bottomStatsBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, dark ? new Color(50, 55, 62) : new Color(220, 224, 230)),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)
        ));

        JPanel statsLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 2));
        statsLeft.setOpaque(false);

        JLabel statsTitle = new JLabel("Statistics");
        statsTitle.setFont(new Font("Segoe UI", Font.BOLD, 12));
        statsTitle.setForeground(dark ? new Color(255, 122, 69) : new Color(227, 86, 0));

        statsLabel = new JLabel("Domains: 0 | Requests: 0 | Selected: 0");
        statsLabel.setFont(new Font("Consolas", Font.PLAIN, 12));
        statsLabel.setForeground(dark ? new Color(201, 209, 217) : new Color(74, 85, 104));

        statsLeft.add(statsTitle);
        statsLeft.add(new JSeparator(SwingConstants.VERTICAL));
        statsLeft.add(statsLabel);

        JPanel footerRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 2));
        footerRight.setOpaque(false);
        JLabel authorLink = new JLabel("bhavymorvadiya.netlify.app");
        authorLink.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        Color linkColor = dark ? new Color(88, 166, 255) : new Color(9, 105, 218);
        Color hoverColor = dark ? new Color(140, 195, 255) : new Color(3, 76, 168);
        authorLink.setForeground(linkColor);
        authorLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
        authorLink.setToolTipText("Open https://bhavymorvadiya.netlify.app/");
        authorLink.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                try {
                    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                        Desktop.getDesktop().browse(new java.net.URI("https://bhavymorvadiya.netlify.app/"));
                    }
                } catch (Exception ignored) {}
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                authorLink.setForeground(hoverColor);
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                authorLink.setForeground(linkColor);
            }
        });
        footerRight.add(authorLink);

        bottomStatsBar.add(statsLeft, BorderLayout.WEST);
        bottomStatsBar.add(footerRight, BorderLayout.EAST);
        add(bottomStatsBar, BorderLayout.SOUTH);

        // -------------------------------------------------------------
        // Listeners & Auto-Sync
        // -------------------------------------------------------------
        DocumentListener docListener = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilters(); }
            public void removeUpdate(DocumentEvent e) { applyFilters(); }
            public void changedUpdate(DocumentEvent e) { applyFilters(); }
        };
        searchField.getDocument().addDocumentListener(docListener);
        apiPathField.getDocument().addDocumentListener(docListener);
        statusCodesField.getDocument().addDocumentListener(docListener);
        contentTypeField.getDocument().addDocumentListener(docListener);

        searchScopeCombo.addActionListener(e -> applyFilters());
        caseSensitiveCheck.addActionListener(e -> applyFilters());
        regexModeCheck.addActionListener(e -> applyFilters());
        invertMatchCheck.addActionListener(e -> applyFilters());
        statusCategoryCombo.addActionListener(e -> applyFilters());
        mimeCategoryCombo.addActionListener(e -> applyFilters());
        timeRangeCombo.addActionListener(e -> applyFilters());
        authEndpointsCheck.addActionListener(e -> applyFilters());

        scopeBothRadio.addActionListener(e -> applyFilters());
        scopeReqOnlyRadio.addActionListener(e -> applyFilters());
        scopeRespOnlyRadio.addActionListener(e -> applyFilters());
        inScopeCheck.addActionListener(e -> {
            if (liveHandler != null) {
                liveHandler.setInScopeOnly(inScopeCheck.isSelected());
            }
            applyFilters();
        });

        trafficTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateSelectionDetails();
            }
        });

        store.addListener(this::refreshData);
        refreshData();
    }

    private void onSelectRangeClicked() {
        try {
            int from = Integer.parseInt(fromNumField.getText().trim());
            int to = Integer.parseInt(toNumField.getText().trim());
            if (from > to) { int t = from; from = to; to = t; }
            int checked = 0;
            for (TrafficRecord r : store.getAllRecords()) {
                if (r.getSequenceNumber() >= from && r.getSequenceNumber() <= to) {
                    selectedRecordIds.add(r.getRecordId());
                    checked++;
                }
            }
            tableModel.fireTableDataChanged();
            updateStatsBar();
            JOptionPane.showMessageDialog(this, String.format("Selected %d records (from #%d to #%d).", checked, from, to), "Range Selected", JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Please enter valid numbers in Range From and To.", "Invalid Range", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onFilterRangeClicked() {
        try {
            activeRangeFrom = Integer.parseInt(fromNumField.getText().trim());
            activeRangeTo = Integer.parseInt(toNumField.getText().trim());
            if (activeRangeFrom > activeRangeTo) {
                int t = activeRangeFrom; activeRangeFrom = activeRangeTo; activeRangeTo = t;
            }
            applyFilters();
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Please enter valid numbers in Range From and To.", "Invalid Range", JOptionPane.WARNING_MESSAGE);
        }
    }

    private boolean isDarkMode() {
        Color bg = UIManager.getColor("Panel.background");
        if (bg == null) return false;
        double luminance = (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) / 255.0;
        return luminance < 0.5;
    }

    private void updateLiveCaptureButtonStyle() {
        boolean dark = isDarkMode();
        liveCaptureBtn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        if (liveCaptureBtn.isSelected()) {
            liveCaptureBtn.setText("● LIVE CAPTURE ON");
            liveCaptureBtn.setBackground(dark ? new Color(18, 55, 32) : new Color(220, 245, 225));
            liveCaptureBtn.setForeground(dark ? new Color(74, 222, 128) : new Color(22, 101, 52));
            liveCaptureBtn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(dark ? new Color(34, 197, 94) : new Color(74, 222, 128), 1, true),
                    BorderFactory.createEmptyBorder(4, 10, 4, 10)
            ));
        } else {
            liveCaptureBtn.setText("○ CAPTURE PAUSED");
            liveCaptureBtn.setBackground(dark ? new Color(42, 47, 54) : new Color(238, 240, 243));
            liveCaptureBtn.setForeground(dark ? new Color(155, 165, 175) : new Color(110, 115, 125));
            liveCaptureBtn.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(dark ? new Color(60, 66, 75) : new Color(205, 210, 215), 1, true),
                    BorderFactory.createEmptyBorder(4, 10, 4, 10)
            ));
        }
    }

    private JTextArea createTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    public void refreshData() {
        domainTreePanel.refreshDomains();
        applyFilters();
    }

    private void applyFilters() {
        TrafficFilter filter = new TrafficFilter();

        // 1. Advanced Traffic Search (Deep full-text with scope, regex, case-sensitivity, invert)
        SearchScope scope = (SearchScope) searchScopeCombo.getSelectedItem();
        filter.setAdvancedSearch(
                searchField.getText(),
                scope != null ? scope : SearchScope.EVERYWHERE,
                caseSensitiveCheck.isSelected(),
                regexModeCheck.isSelected(),
                invertMatchCheck.isSelected()
        );

        // 2. Smart Filters: Status codes & categories
        String statusGroup = (String) statusCategoryCombo.getSelectedItem();
        if (statusGroup != null) {
            if (statusGroup.startsWith("2xx")) filter.setStatusCodeGroup("2xx");
            else if (statusGroup.startsWith("3xx")) filter.setStatusCodeGroup("3xx");
            else if (statusGroup.startsWith("4xx")) filter.setStatusCodeGroup("4xx");
            else if (statusGroup.startsWith("5xx")) filter.setStatusCodeGroup("5xx");
            else if (statusGroup.contains("401") || statusGroup.contains("Auth")) filter.setStatusCodeGroup("AUTH_ERRORS");
            else filter.setStatusCodeGroup("ALL");
        }
        filter.setStatusCodeCustom(statusCodesField.getText());

        // 3. Smart Filters: MIME type categories & custom
        MimeCategory mimeCat = (MimeCategory) mimeCategoryCombo.getSelectedItem();
        filter.setMimeCategory(mimeCat != null ? mimeCat : MimeCategory.ALL);
        filter.setMimeCustom(contentTypeField.getText());

        // 4. Smart Filters: Time range & Auth endpoints
        TimeRangeMode timeMode = (TimeRangeMode) timeRangeCombo.getSelectedItem();
        filter.setTimeRangeMode(timeMode != null ? timeMode : TimeRangeMode.ALL_TIME);
        filter.setAuthEndpointsOnly(authEndpointsCheck.isSelected());

        filter.setEndpointPath(apiPathField.getText());
        filter.setInScopeOnly(inScopeCheck.isSelected());
        filter.setRange(activeRangeFrom, activeRangeTo);
        filter.setExcludeStaticAssets(excludeStaticCheck.isSelected());

        // Domain selection
        Set<String> selHosts = domainTreePanel.getSelectedHosts();
        if (selHosts != null && !selHosts.isEmpty()) {
            filter.setEnabledDomains(selHosts);
        }

        // Method checkboxes
        Set<String> activeMethods = new HashSet<>();
        for (Map.Entry<String, JCheckBox> entry : methodCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                activeMethods.add(entry.getKey());
            }
        }
        filter.setEnabledMethods(activeMethods);

        // Selection filter
        String selFilterStr = (String) selectionFilterCombo.getSelectedItem();
        if ("Selected Only".equals(selFilterStr)) {
            filter.setSelectionFilter("SELECTED", selectedRecordIds);
        } else if ("Unselected Only".equals(selFilterStr)) {
            filter.setSelectionFilter("UNSELECTED", selectedRecordIds);
        } else {
            filter.setSelectionFilter("ALL", selectedRecordIds);
        }

        List<TrafficRecord> all = store.getAllRecords();
        List<TrafficRecord> filtered = filter.filter(all);

        // Remove duplicate URLs if checked
        if (removeDuplicatesCheck.isSelected()) {
            Map<String, TrafficRecord> latestMap = new LinkedHashMap<>();
            for (TrafficRecord r : filtered) {
                latestMap.put(r.getMethod() + " " + r.getUrl(), r);
            }
            displayedRecords = new ArrayList<>(latestMap.values());
        } else {
            displayedRecords = filtered;
        }

        tableModel.fireTableDataChanged();
        updatePreview();
        updateStatsBar();
        updateSelectionDetails();
    }

    private void updatePreview() {
        StringBuilder sb = new StringBuilder();
        int previewCount = Math.min(5, displayedRecords.size());

        for (int i = 0; i < previewCount; i++) {
            TrafficRecord r = displayedRecords.get(i);
            sb.append("Host: ").append(r.getHost()).append("\n");
            for (String h : r.getRequestHeaders()) {
                sb.append(h).append("\n");
            }
            String reqBody = r.getRequestBodyAsString();
            if (!reqBody.isEmpty()) {
                sb.append("\n").append(reqBody).append("\n");
            }
            sb.append("\n--- RESPONSE ---\n");
            if (r.hasResponse()) {
                sb.append("HTTP/1.1 ").append(r.getStatusCode()).append(" ").append(r.getStatusReason()).append("\n");
                for (String h : r.getResponseHeaders()) {
                    sb.append(h).append("\n");
                }
                String resBody = r.getResponseBodyAsString();
                if (!resBody.isEmpty()) {
                    sb.append("\n").append(resBody).append("\n");
                }
            } else {
                sb.append("[No response recorded]\n");
            }
            sb.append("\n================================================================================\n\n");
        }
        previewArea.setText(sb.toString());
        previewArea.setCaretPosition(0);
    }

    private void updateStatsBar() {
        Set<String> uniqueDomains = new HashSet<>();
        int getCount = 0, postCount = 0, putCount = 0, delCount = 0;
        int status2xx = 0, status3xx = 0, status4xx = 0, status5xx = 0;

        for (TrafficRecord r : displayedRecords) {
            uniqueDomains.add(r.getHost());
            String m = r.getMethod().toUpperCase();
            if ("GET".equals(m)) getCount++;
            else if ("POST".equals(m)) postCount++;
            else if ("PUT".equals(m)) putCount++;
            else if ("DELETE".equals(m)) delCount++;

            int code = r.getStatusCode();
            if (code >= 200 && code < 300) status2xx++;
            else if (code >= 300 && code < 400) status3xx++;
            else if (code >= 400 && code < 500) status4xx++;
            else if (code >= 500 && code < 600) status5xx++;
        }

        String stats = String.format("Domains: %d | Requests: %d  GET:%d  POST:%d  PUT:%d  DEL:%d  2xx:%d  3xx:%d  4xx:%d  5xx:%d | Selected: %d",
                uniqueDomains.size(), displayedRecords.size(), getCount, postCount, putCount, delCount, status2xx, status3xx, status4xx, status5xx, selectedRecordIds.size());
        statsLabel.setText(stats);
    }

    private void updateSelectionDetails() {
        int[] rows = trafficTable.getSelectedRows();

        if (rows.length == 0) {
            reqArea.setText("");
            respArea.setText("");
            metadataArea.setText("");
            return;
        }

        int modelRow = trafficTable.convertRowIndexToModel(rows[0]);
        if (modelRow >= 0 && modelRow < displayedRecords.size()) {
            TrafficRecord r = displayedRecords.get(modelRow);

            // Request
            StringBuilder reqSb = new StringBuilder();
            for (String h : r.getRequestHeaders()) reqSb.append(h).append("\n");
            reqSb.append("\n");
            reqSb.append(r.getRequestBodyAsString());
            reqArea.setText(reqSb.toString());
            reqArea.setCaretPosition(0);

            // Response
            StringBuilder resSb = new StringBuilder();
            if (r.hasResponse()) {
                for (String h : r.getResponseHeaders()) resSb.append(h).append("\n");
                resSb.append("\n");
                resSb.append(r.getResponseBodyAsString());
            } else {
                resSb.append("[NO RESPONSE AVAILABLE]");
            }
            respArea.setText(resSb.toString());
            respArea.setCaretPosition(0);

            // Metadata & Integrity
            StringBuilder meta = new StringBuilder();
            meta.append("=== EVIDENCE METADATA & INTEGRITY ===\n\n");
            meta.append(String.format("Record #:        #%d\n", r.getSequenceNumber()));
            meta.append(String.format("Record ID:       %s\n", r.getRecordId()));
            meta.append(String.format("Engagement:      %s\n", r.getEngagementId()));
            meta.append(String.format("Full URL:        %s\n", r.getUrl()));
            meta.append(String.format("Target Host:     %s:%d (%s)\n", r.getHost(), r.getPort(), r.getProtocol()));
            meta.append(String.format("Method & Path:   %s %s\n", r.getMethod(), r.getPath()));
            meta.append(String.format("Status Code:     %d %s\n", r.getStatusCode(), r.getStatusReason()));
            meta.append(String.format("Content-Type:    %s\n", r.getContentType()));
            meta.append(String.format("Request Size:    %d bytes\n", r.getRequestSize()));
            meta.append(String.format("Response Size:   %d bytes\n", r.getResponseSize()));
            meta.append(String.format("Duration:        %d ms\n", r.getDurationMs()));
            meta.append(String.format("Source Tool:     %s\n", r.getSourceTool()));
            meta.append(String.format("In Scope:        %s\n\n", r.isInScope()));
            meta.append("--- CRYPTOGRAPHIC HASHES (SHA-256) ---\n");
            meta.append(String.format("Request Hash:    %s\n", r.getRequestHash()));
            meta.append(String.format("Response Hash:   %s\n", r.getResponseHash() != null ? r.getResponseHash() : "NONE"));
            metadataArea.setText(meta.toString());
            metadataArea.setCaretPosition(0);
        }
    }

    private List<TrafficRecord> getSelectedOrDisplayedRecords() {
        List<TrafficRecord> targets = new ArrayList<>();
        if (!selectedRecordIds.isEmpty()) {
            for (TrafficRecord r : store.getAllRecords()) {
                if (selectedRecordIds.contains(r.getRecordId())) {
                    targets.add(r);
                }
            }
        }
        if (targets.isEmpty()) {
            int[] rows = trafficTable.getSelectedRows();
            if (rows.length > 0) {
                for (int r : rows) {
                    int modelIdx = trafficTable.convertRowIndexToModel(r);
                    targets.add(displayedRecords.get(modelIdx));
                }
            }
        }
        if (targets.isEmpty()) {
            targets = new ArrayList<>(displayedRecords);
        }
        return targets;
    }

    private void copySelected(String format) {
        List<TrafficRecord> targets = getSelectedOrDisplayedRecords();
        if (targets.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No records to copy. Please capture or select traffic first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        if ("JSON".equalsIgnoreCase(format)) {
            ClipboardHelper.copyAsJson(targets, true);
        } else if ("CSV".equalsIgnoreCase(format)) {
            ClipboardHelper.copyAsCsv(targets);
        } else if ("HTML".equalsIgnoreCase(format)) {
            ClipboardHelper.copyAsHtml(targets, true);
        } else if ("MARKDOWN".equalsIgnoreCase(format)) {
            ClipboardHelper.copyAsMarkdown(targets, true);
        }

        JOptionPane.showMessageDialog(this,
                String.format("Copied %d transaction(s) to clipboard as %s!", targets.size(), format.toUpperCase()),
                "Copied to Clipboard",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void onExportClicked() {
        List<TrafficRecord> toExport = getSelectedOrDisplayedRecords();
        if (toExport.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No records to export. Please capture or select traffic first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Frame parentFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, this);
        ExportDialog dialog = new ExportDialog(parentFrame, toExport);
        dialog.setVisible(true);
    }

    private void showPresetMenu(Component invoker) {
        JPopupMenu menu = new JPopupMenu();
        List<ExportPreset> presets = presetManager.getAllPresets();
        for (ExportPreset p : presets) {
            JMenuItem item = new JMenuItem(p.getName());
            item.setToolTipText(p.getDescription());
            item.addActionListener(e -> onQuickPresetExport(p));
            menu.add(item);
        }
        menu.addSeparator();
        JMenuItem customItem = new JMenuItem("Custom Presets & All Options...");
        customItem.addActionListener(e -> onExportClicked());
        menu.add(customItem);
        menu.show(invoker, 0, invoker.getHeight());
    }

    private void onQuickPresetExport(ExportPreset preset) {
        List<TrafficRecord> toExport = getSelectedOrDisplayedRecords();
        if (toExport.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No records to export. Please capture or select traffic first.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Frame parentFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, this);
        ExportDialog dialog = new ExportDialog(parentFrame, toExport, preset);
        dialog.setVisible(true);
    }

    private void onCompareClicked() {
        List<TrafficRecord> compareCandidates = new ArrayList<>();
        if (selectedRecordIds.size() == 2) {
            for (TrafficRecord r : store.getAllRecords()) {
                if (selectedRecordIds.contains(r.getRecordId())) {
                    compareCandidates.add(r);
                }
            }
        }
        if (compareCandidates.size() != 2) {
            int[] rows = trafficTable.getSelectedRows();
            if (rows.length == 2) {
                int row1 = trafficTable.convertRowIndexToModel(rows[0]);
                int row2 = trafficTable.convertRowIndexToModel(rows[1]);
                compareCandidates.add(displayedRecords.get(row1));
                compareCandidates.add(displayedRecords.get(row2));
            }
        }
        if (compareCandidates.size() != 2) {
            JOptionPane.showMessageDialog(this, "Please check (or highlight) exactly 2 records to compare responses.", "Notice", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        TrafficRecord a = compareCandidates.get(0);
        TrafficRecord b = compareCandidates.get(1);
        if (comparePanel != null) {
            comparePanel.setRecordsToCompare(a, b);
            Container parent = getParent();
            while (parent != null && !(parent instanceof JTabbedPane)) {
                parent = parent.getParent();
            }
            if (parent instanceof JTabbedPane) {
                ((JTabbedPane) parent).setSelectedComponent(comparePanel);
            }
        }
    }

    // Table Model with 1st Column Selection Checkbox and Record Sequence #
    private class TrafficTableModel extends AbstractTableModel {
        private final String[] columns = {"Select", "#", "Method", "Host", "Path", "Status", "Content-Type", "Size", "Source"};

        @Override
        public int getRowCount() { return displayedRecords.size(); }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public String getColumnName(int column) { return columns[column]; }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Boolean.class;
            if (columnIndex == 1) return Integer.class;
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= displayedRecords.size()) return null;
            TrafficRecord r = displayedRecords.get(rowIndex);
            switch (columnIndex) {
                case 0: return selectedRecordIds.contains(r.getRecordId());
                case 1: return r.getSequenceNumber();
                case 2: return r.getMethod();
                case 3: return r.getHost();
                case 4: return r.getPath();
                case 5: return r.getStatusCode() > 0 ? String.valueOf(r.getStatusCode()) : "-";
                case 6: return r.getContentType();
                case 7: return r.getResponseSize() + " B";
                case 8: return r.getSourceTool();
                default: return null;
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && aValue instanceof Boolean && rowIndex >= 0 && rowIndex < displayedRecords.size()) {
                TrafficRecord r = displayedRecords.get(rowIndex);
                boolean checked = (Boolean) aValue;
                if (checked) {
                    selectedRecordIds.add(r.getRecordId());
                } else {
                    selectedRecordIds.remove(r.getRecordId());
                }
                fireTableCellUpdated(rowIndex, columnIndex);
                updateStatsBar();
                String selFilterStr = (String) selectionFilterCombo.getSelectedItem();
                if (!"All Records".equals(selFilterStr)) {
                    applyFilters();
                }
            }
        }
    }
}
