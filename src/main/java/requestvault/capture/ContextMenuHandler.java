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
        List<HttpRequestResponse> selectedMessages = new ArrayList<>();
        if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
            selectedMessages.addAll(event.selectedRequestResponses());
        } else if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse editorMsg = event.messageEditorRequestResponse().get().requestResponse();
            if (editorMsg != null && editorMsg.request() != null) {
                selectedMessages.add(editorMsg);
            }
        }

        if (selectedMessages.isEmpty()) {
            return null;
        }

        List<Component> menuList = new ArrayList<>();
        final int count = selectedMessages.size();

        // 1. Primary Action: Copy this request as cURL directly at the top level
        String curlTitle = count == 1 ? "Copy this request as cURL" : String.format("Copy requests as cURL (%d)", count);
        JMenuItem copyCurlTop = new JMenuItem(curlTitle);
        copyCurlTop.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsCurl(records);
            api.logging().logToOutput(String.format("[RequestVault] Copied %d request(s) to clipboard as cURL command.", records.size()));
            JOptionPane.showMessageDialog(null,
                    String.format("Copied %d request(s) to clipboard as cURL!\n\nReady to paste into terminal / bash.", records.size()),
                    "Copied as cURL",
                    JOptionPane.INFORMATION_MESSAGE);
        });
        menuList.add(copyCurlTop);

        // 2. Replay Code Submenu (Python, JS Fetch, PowerShell, Raw HTTP)
        JMenu replaySubmenu = new JMenu(String.format("Copy Replay Code (%d)", count));

        JMenuItem copyCurlSub = new JMenuItem("cURL Command");
        copyCurlSub.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsCurl(records);
            JOptionPane.showMessageDialog(null, String.format("Copied %d request(s) to clipboard as cURL!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyPython = new JMenuItem("Python (requests)");
        copyPython.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsPython(records);
            api.logging().logToOutput(String.format("[RequestVault] Copied %d request(s) to clipboard as Python script.", records.size()));
            JOptionPane.showMessageDialog(null, String.format("Copied %d request(s) to clipboard as Python Script!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyFetch = new JMenuItem("JavaScript (fetch)");
        copyFetch.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsFetch(records);
            api.logging().logToOutput(String.format("[RequestVault] Copied %d request(s) to clipboard as JavaScript Fetch.", records.size()));
            JOptionPane.showMessageDialog(null, String.format("Copied %d request(s) to clipboard as JavaScript Fetch!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyPowerShell = new JMenuItem("PowerShell (Invoke-RestMethod)");
        copyPowerShell.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsPowerShell(records);
            api.logging().logToOutput(String.format("[RequestVault] Copied %d request(s) to clipboard as PowerShell.", records.size()));
            JOptionPane.showMessageDialog(null, String.format("Copied %d request(s) to clipboard as PowerShell!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        JMenuItem copyRaw = new JMenuItem("Raw HTTP (RFC 7230)");
        copyRaw.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ClipboardHelper.copyAsRawHttp(records);
            api.logging().logToOutput(String.format("[RequestVault] Copied %d request(s) to clipboard as Raw HTTP.", records.size()));
            JOptionPane.showMessageDialog(null, String.format("Copied %d request(s) to clipboard as Raw HTTP!", records.size()), "Copied to Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });

        replaySubmenu.add(copyCurlSub);
        replaySubmenu.add(copyPython);
        replaySubmenu.add(copyFetch);
        replaySubmenu.add(copyPowerShell);
        replaySubmenu.add(copyRaw);
        menuList.add(replaySubmenu);

        menuList.add(new JSeparator());

        // 3. Send to RequestVault
        JMenuItem sendItem = new JMenuItem(String.format("Send to RequestVault (%d)", count));
        sendItem.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            int added = store.addRecords(records, true);
            JOptionPane.showMessageDialog(null, String.format("Imported %d new transaction(s) into RequestVault (%d duplicates skipped).", added, records.size() - added), "RequestVault", JOptionPane.INFORMATION_MESSAGE);
        });
        menuList.add(sendItem);

        // 4. Evidence Copy Submenu (JSON, CSV, HTML, Markdown)
        JMenu copySubmenu = new JMenu(String.format("Copy Evidence Formats (%d)", count));

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
        menuList.add(copySubmenu);

        // 5. Quick Export Selected Flow
        JMenuItem exportItem = new JMenuItem(String.format("Export Evidence Pack (%d)...", count));
        exportItem.addActionListener(e -> {
            List<TrafficRecord> records = toRecords(selectedMessages);
            ExportDialog dialog = new ExportDialog(null, records);
            dialog.setVisible(true);
        });
        menuList.add(exportItem);

        // 6. Compare if exactly 2 items selected
        if (count == 2) {
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
