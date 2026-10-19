package requestvault.capture;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

public class LiveProxyCaptureHandler implements ProxyResponseHandler {

    private final MontoyaApi api;
    private final TrafficStore store;
    private volatile boolean enabled = true;
    private volatile boolean inScopeOnly = false;

    public LiveProxyCaptureHandler(MontoyaApi api, TrafficStore store) {
        this.api = api;
        this.store = store;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isInScopeOnly() { return inScopeOnly; }
    public void setInScopeOnly(boolean inScopeOnly) { this.inScopeOnly = inScopeOnly; }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (enabled && interceptedResponse != null) {
            try {
                boolean inScope = false;
                try {
                    if (interceptedResponse.initiatingRequest() != null) {
                        inScope = api.scope().isInScope(interceptedResponse.initiatingRequest().url());
                    }
                } catch (Exception ignored) {}

                if (!inScopeOnly || inScope) {
                    TrafficRecord record = TrafficCapture.fromInterceptedResponse(interceptedResponse, inScope);
                    if (record != null) {
                        store.addRecord(record, true);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("RequestVault live capture error: " + e.getMessage());
            }
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
