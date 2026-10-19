package requestvault.capture;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

import javax.swing.SwingWorker;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class ProxyHistoryImporter {

    public static void importHistoryAsync(MontoyaApi api, TrafficStore store, boolean inScopeOnly, Consumer<Integer> onComplete) {
        SwingWorker<Integer, Void> worker = new SwingWorker<Integer, Void>() {
            @Override
            protected Integer doInBackground() {
                List<ProxyHttpRequestResponse> historyList = api.proxy().history();
                if (historyList == null || historyList.isEmpty()) {
                    return 0;
                }

                List<TrafficRecord> records = new ArrayList<>();
                for (ProxyHttpRequestResponse item : historyList) {
                    boolean inScope = false;
                    try {
                        HttpRequest req = item.finalRequest() != null ? item.finalRequest() : item.request();
                        if (req != null && req.url() != null) {
                            inScope = api.scope().isInScope(req.url());
                        }
                    } catch (Exception ignored) {}

                    if (!inScopeOnly || inScope) {
                        TrafficRecord r = TrafficCapture.fromProxyMessage(item, inScope);
                        if (r != null) {
                            records.add(r);
                        }
                    }
                }
                return store.addRecords(records, true);
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    if (onComplete != null) {
                        onComplete.accept(count);
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error importing proxy history: " + e.getMessage());
                    if (onComplete != null) {
                        onComplete.accept(0);
                    }
                }
            }
        };
        worker.execute();
    }
}
