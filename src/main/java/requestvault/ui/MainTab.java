package requestvault.ui;

import burp.api.montoya.MontoyaApi;
import requestvault.capture.LiveProxyCaptureHandler;
import requestvault.capture.ProxyHistoryImporter;
import requestvault.storage.TrafficStore;

import javax.swing.*;
import java.awt.*;

public class MainTab extends JPanel {

    private final MontoyaApi api;
    private final TrafficStore store;
    private final LiveProxyCaptureHandler liveHandler;
    private final TrafficPanel trafficPanel;
    private final ComparePanel comparePanel;
    private final JTabbedPane tabbedPane;

    public MainTab(MontoyaApi api, TrafficStore store, LiveProxyCaptureHandler liveHandler) {
        this.api = api;
        this.store = store;
        this.liveHandler = liveHandler;

        setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();
        comparePanel = new ComparePanel(store);
        trafficPanel = new TrafficPanel(api, store, comparePanel, liveHandler);

        tabbedPane.addTab("Traffic & Evidence", trafficPanel);
        tabbedPane.addTab("Response Diff", comparePanel);
        tabbedPane.addTab("Engagements & Settings", createSettingsPanel());

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 8, 8, 8);

        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        JLabel title = new JLabel("RequestVault Configuration");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
        panel.add(title, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(new JLabel("Active Engagement Name:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JTextField engagementField = new JTextField(store.getCurrentEngagement() != null ? store.getCurrentEngagement().getName() : "Engagement-1");
        panel.add(engagementField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(new JLabel("Storage & Redaction Policy:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        JLabel policyInfo = new JLabel("<html><b>Local-First Immutable Evidence:</b> Original request/response bytes are strictly preserved in raw format.<br/>Sanitization rules are only executed upon export copies, protecting original VAPT reproducibility.</html>");
        panel.add(policyInfo, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
        JButton saveBtn = new JButton("Update Engagement Name");
        saveBtn.addActionListener(e -> {
            if (store.getCurrentEngagement() != null) {
                store.getCurrentEngagement().setName(engagementField.getText().trim());
                JOptionPane.showMessageDialog(this, "Engagement name updated to: " + engagementField.getText().trim(), "Updated", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        panel.add(saveBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        JButton loadHistoryBtn = new JButton("Reload / Re-sync All Proxy HTTP History");
        loadHistoryBtn.addActionListener(e -> {
            loadHistoryBtn.setEnabled(false);
            ProxyHistoryImporter.importHistoryAsync(api, store, false, count -> {
                loadHistoryBtn.setEnabled(true);
                JOptionPane.showMessageDialog(this, "Reloaded " + count + " record(s) from Proxy HTTP History.", "Complete", JOptionPane.INFORMATION_MESSAGE);
            });
        });
        panel.add(loadHistoryBtn, gbc);

        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        JPanel aboutCard = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        aboutCard.setBorder(BorderFactory.createTitledBorder("About RequestVault"));
        JLabel websiteLabel = new JLabel("<html><b>Author & Website:</b> <a href='https://bhavymorvadiya.netlify.app/' style='color:#0969da;'>https://bhavymorvadiya.netlify.app/</a></html>");
        websiteLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        websiteLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        websiteLabel.setToolTipText("Open https://bhavymorvadiya.netlify.app/");
        websiteLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                try {
                    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                        Desktop.getDesktop().browse(new java.net.URI("https://bhavymorvadiya.netlify.app/"));
                    }
                } catch (Exception ignored) {}
            }
        });
        aboutCard.add(websiteLabel);
        panel.add(aboutCard, gbc);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(panel, BorderLayout.NORTH);
        return wrapper;
    }

    public TrafficPanel getTrafficPanel() { return trafficPanel; }
    public ComparePanel getComparePanel() { return comparePanel; }
    public JTabbedPane getTabbedPane() { return tabbedPane; }
}
