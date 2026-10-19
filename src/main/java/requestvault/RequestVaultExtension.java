package requestvault;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import requestvault.capture.ContextMenuHandler;
import requestvault.capture.LiveProxyCaptureHandler;
import requestvault.capture.ProxyHistoryImporter;
import requestvault.storage.TrafficStore;
import requestvault.ui.MainTab;

public class RequestVaultExtension implements BurpExtension {

    private MontoyaApi api;
    private TrafficStore store;
    private MainTab mainTab;
    private LiveProxyCaptureHandler liveHandler;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.store = new TrafficStore();

        api.extension().setName("RequestVault");

        Logging logging = api.logging();
        logging.logToOutput("=================================================");
        logging.logToOutput(" RequestVault - Local-First Evidence & Flow Tool ");
        logging.logToOutput(" Version: 0.1.0-MVP (Java 21/Montoya API)         ");
        logging.logToOutput("=================================================");

        // 1. Register Live Proxy Capture Handler
        liveHandler = new LiveProxyCaptureHandler(api, store);
        api.proxy().registerResponseHandler(liveHandler);
        logging.logToOutput("[+] Live Proxy capture enabled (auto-capturing requests and paired responses).");

        // 2. Register UI Suite Tab
        mainTab = new MainTab(api, store, liveHandler);
        api.userInterface().registerSuiteTab("RequestVault", mainTab);

        // 3. Register Context Menu Provider
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuHandler(api, store, mainTab));

        // 4. Auto-load existing Proxy HTTP History in background
        logging.logToOutput("[*] Loading existing Proxy HTTP History...");
        ProxyHistoryImporter.importHistoryAsync(api, store, false, count -> {
            logging.logToOutput("[+] Auto-loaded " + count + " existing transaction(s) from Proxy HTTP History.");
        });

        logging.logToOutput("[+] RequestVault extension initialized successfully.");
    }
}
