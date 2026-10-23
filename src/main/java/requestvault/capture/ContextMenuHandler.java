package requestvault.capture;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import requestvault.export.ClipboardHelper;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;
import requestvault.ui.ExportDialog;
import requestvault.ui.MainTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuHandler implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final TrafficStore store;
    private final MainTab mainTab;

    public ContextMenuHandler(MontoyaApi api, TrafficStore store, MainTab mainTab) {
        this.api = api;
        this.store = store;
        this.mainTab = mainTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
        if (selectedMessages == null || selectedMessages.isEmpty()) {
            return null;
        }

        List<Component> menuList = new ArrayList<>();

        // Menu 1: Send to RequestVault
        JMenuItem sendItem = new JMenuItem(String.format("Send to RequestVault (%d)", selectedMessages.size()));
        sendItem.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            int added = store.addRecords(records, true);
            JOptionPane.showMessageDialog(null, String.format("Imported %d new transaction(s) into RequestVault (%d duplicates skipped).", added, records.size() - added), "RequestVault", JOptionPane.INFORMATION_MESSAGE);
        });
        menuList.add(sendItem);

        // Menu 2: One-Click Copy submenu
        JMenu copySubmenu = new JMenu(String.format("RequestVault: One-Click Copy (%d)", selectedMessages.size()));

        JMenuItem copyJson = new JMenuItem("Copy as JSON");
        copyJson.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsJson(records, true);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as JSON!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyCsv = new JMenuItem("Copy as CSV");
        copyCsv.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsCsv(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as CSV!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyHtml = new JMenuItem("Copy as HTML");
        copyHtml.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsHtml(records, true);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as HTML!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyMd = new JMenuItem("Copy as Markdown (VAPT Report)");
        copyMd.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsMarkdown(records, true);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as Markdown!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        copySubmenu.add(copyJson);
        copySubmenu.add(copyCsv);
        copySubmenu.add(copyHtml);
        copySubmenu.add(copyMd);
        copySubmenu.addSeparator();

        JMenuItem copyCurl = new JMenuItem("Copy as cURL");
        copyCurl.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsCurl(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as cURL!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyPython = new JMenuItem("Copy as Python (requests)");
        copyPython.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsPython(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as Python Script!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyFetch = new JMenuItem("Copy as JavaScript (fetch)");
        copyFetch.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsFetch(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as JavaScript Fetch!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyPowerShell = new JMenuItem("Copy as PowerShell");
        copyPowerShell.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsPowerShell(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as PowerShell!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyRaw = new JMenuItem("Copy as Raw HTTP (RFC 7230)");
        copyRaw.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsRawHttp(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d transaction(s) to clipboard as Raw HTTP!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        copySubmenu.add(copyCurl);
        copySubmenu.add(copyPython);
        copySubmenu.add(copyFetch);
        copySubmenu.add(copyPowerShell);
        copySubmenu.add(copyRaw);

        menuList.add(copySubmenu);

        // Menu 3: Quick Export Selected
        JMenuItem exportItem = new JMenuItem(String.format("RequestVault: Export Selected Flow (%d)...", selectedMessages.size()));
        exportItem.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ExportDialog dialog = new ExportDialog(null, records);
            dialog.setVisible(true);
        });
        menuList.add(exportItem);

        // Menu 4: Compare if exactly 2 items selected
        if (selectedMessages.size() == 2) {
            JMenuItem compareItem = new JMenuItem("RequestVault: Compare 2 Responses Side-by-Side");
            compareItem.addActionListener(e -> {
                TrafficRecord r1 = TrafficCapture.fromMontoya(selectedMessages.get(0), "CompareA", false);
                TrafficRecord r2 = TrafficCapture.fromMontoya(selectedMessages.get(1), "CompareB", false);
                store.addRecord(r1, false);
                store.addRecord(r2, false);
                mainTab.getComparePanel().setRecordsToCompare(r1, r2);
                mainTab.getTabbedPane().setSelectedComponent(mainTab.getComparePanel());
            });
            menuList.add(compareItem);
        }

        return menuList;
    }

    private List<TrafficRecord> toRecords(List<HttpRequestResponse> messages) {
        List<TrafficRecord> records = new ArrayList<>();
        for (HttpRequestResponse msg : messages) {
            boolean inScope = false;
            try {
                if (msg.request() != null && msg.request().url() != null) {
                    inScope = api.scope().isInScope(msg.request().url());
                }
            } catch (Exception ignored) {}
            TrafficRecord r = TrafficCapture.fromMontoya(msg, "Selection", inScope);
            if (r != null) {
                records.add(r);
            }
        }
        return records;
    }
}
