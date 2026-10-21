package requestvault.analysis;

import requestvault.model.TrafficRecord;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Advanced multi-criteria search and smart filtering engine for HTTP traffic.
 * Supports:
 * - Smart Filters: Host, Subdomains, MIME types, Status categories & ranges, Time ranges, and Authentication endpoints.
 * - Advanced Traffic Search: Deep full-text search across URLs, Headers, Bodies, Parameters, Statuses, and Methods with Regex and Case-Sensitivity.
 */
public class TrafficFilter {

    public enum SearchScope {
        EVERYWHERE("Everywhere"),
        URL("URL & Path"),
        HEADERS("Headers (Req + Resp)"),
        REQ_BODY("Request Body"),
        RESP_BODY("Response Body"),
        PARAMS("Parameters (Query & Body)"),
        STATUS("Status Code"),
        METHOD("HTTP Method");

        private final String displayName;
        SearchScope(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
        @Override public String toString() { return displayName; }
    }

    public enum TimeRangeMode {
        ALL_TIME("All Time"),
        LAST_5_MIN("Last 5 Minutes"),
        LAST_15_MIN("Last 15 Minutes"),
        LAST_1_HOUR("Last 1 Hour"),
        LAST_24_HOURS("Last 24 Hours"),
        CUSTOM("Custom Range");

        private final String displayName;
        TimeRangeMode(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
        @Override public String toString() { return displayName; }
    }

    public enum MimeCategory {
        ALL("All MIME Types"),
        JSON("JSON (application/json)"),
        HTML("HTML (text/html)"),
        XML("XML (application/xml, text/xml)"),
        PLAIN_TEXT("Plain Text (text/plain)"),
        SCRIPT_CSS("Scripts & Stylesheets (js, css)"),
        BINARY_MEDIA("Binary & Media (images, pdf, octet-stream)");

        private final String displayName;
        MimeCategory(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }
        @Override public String toString() { return displayName; }
    }

    // Advanced Search Fields
    private String advancedQuery = "";
    private SearchScope searchScope = SearchScope.EVERYWHERE;
    private boolean caseSensitive = false;
    private boolean regexMode = false;
    private boolean invertMatch = false;
    private Pattern compiledPattern = null;

    // Smart Filters
    private String hostFilter = "";
    private Set<String> enabledDomains = null;
    private Set<String> enabledMethods = null;
    private String endpointPath = "";
    private String statusCodeCustom = "";
    private String statusCodeGroup = "ALL";
    private MimeCategory mimeCategory = MimeCategory.ALL;
    private String mimeCustom = "";
    private TimeRangeMode timeRangeMode = TimeRangeMode.ALL_TIME;
    private Long timeRangeFrom = null;
    private Long timeRangeTo = null;
    private boolean authEndpointsOnly = false;
    private boolean excludeStaticAssets = false;
    private Boolean inScopeOnly = false;
    private String selectionFilter = "ALL";
    private Set<String> selectedRecordIds = null;
    private Integer rangeFrom = null;
    private Integer rangeTo = null;

    private static final Set<String> STATIC_EXTENSIONS = new HashSet<>(Arrays.asList(
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3"
    ));

    private static final List<String> AUTH_PATH_KEYWORDS = Arrays.asList(
            "/auth", "/login", "/logout", "/oauth", "/token", "/saml", "/session",
            "/signin", "/signout", "/jwt", "/authenticate", "/password", "/register",
            "/sso", "/mfa", "/2fa", "/verify", "/user/login", "/api/auth", "/api/v1/auth"
    );

    public TrafficFilter() {}

    // -------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------

    public void setAdvancedSearch(String query, SearchScope scope, boolean caseSensitive, boolean regexMode, boolean invertMatch) {
        this.advancedQuery = query != null ? query.trim() : "";
        this.searchScope = (scope != null) ? scope : SearchScope.EVERYWHERE;
        this.caseSensitive = caseSensitive;
        this.regexMode = regexMode;
        this.invertMatch = invertMatch;

        if (this.regexMode && !this.advancedQuery.isEmpty()) {
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                this.compiledPattern = Pattern.compile(this.advancedQuery, flags);
            } catch (Exception ex) {
                this.compiledPattern = null;
            }
        } else {
            this.compiledPattern = null;
        }
    }

    public void setHostFilter(String hostFilter) {
        this.hostFilter = hostFilter != null ? hostFilter.trim().toLowerCase(Locale.ROOT) : "";
    }

    public void setEnabledDomains(Set<String> enabledDomains) {
        this.enabledDomains = enabledDomains;
    }

    public void setEnabledMethods(Set<String> enabledMethods) {
        this.enabledMethods = enabledMethods;
    }

    public void setEndpointPath(String endpointPath) {
        this.endpointPath = endpointPath != null ? endpointPath.trim().toLowerCase(Locale.ROOT) : "";
    }

    public void setStatusCodeGroup(String statusCodeGroup) {
        this.statusCodeGroup = statusCodeGroup != null ? statusCodeGroup.trim() : "ALL";
    }

    public void setStatusCodeCustom(String statusCodeCustom) {
        this.statusCodeCustom = statusCodeCustom != null ? statusCodeCustom.trim() : "";
    }

    public void setMimeCategory(MimeCategory mimeCategory) {
        this.mimeCategory = mimeCategory != null ? mimeCategory : MimeCategory.ALL;
    }

    public void setMimeCustom(String mimeCustom) {
        this.mimeCustom = mimeCustom != null ? mimeCustom.trim().toLowerCase(Locale.ROOT) : "";
    }

    public void setTimeRangeMode(TimeRangeMode timeRangeMode) {
        this.timeRangeMode = timeRangeMode != null ? timeRangeMode : TimeRangeMode.ALL_TIME;
    }

    public void setCustomTimeRange(Long fromMillis, Long toMillis) {
        this.timeRangeFrom = fromMillis;
        this.timeRangeTo = toMillis;
    }

    public void setAuthEndpointsOnly(boolean authEndpointsOnly) {
        this.authEndpointsOnly = authEndpointsOnly;
    }

    public void setExcludeStaticAssets(boolean excludeStaticAssets) {
        this.excludeStaticAssets = excludeStaticAssets;
    }

    public void setInScopeOnly(Boolean inScopeOnly) {
        this.inScopeOnly = inScopeOnly != null && inScopeOnly;
    }

    public void setSelectionFilter(String selectionFilter, Set<String> selectedRecordIds) {
        this.selectionFilter = selectionFilter != null ? selectionFilter.trim().toUpperCase(Locale.ROOT) : "ALL";
        this.selectedRecordIds = selectedRecordIds;
    }

    public void setRange(Integer rangeFrom, Integer rangeTo) {
        this.rangeFrom = rangeFrom;
        this.rangeTo = rangeTo;
    }

    // -------------------------------------------------------------
    // Match Logic
    // -------------------------------------------------------------

    public boolean matches(TrafficRecord record) {
        if (record == null) return false;

        // 1. Sequence number range check
        if (rangeFrom != null && rangeFrom > 0 && record.getSequenceNumber() < rangeFrom) return false;
        if (rangeTo != null && rangeTo > 0 && record.getSequenceNumber() > rangeTo) return false;

        // 2. Selection state check
        if ("SELECTED".equalsIgnoreCase(selectionFilter)) {
            if (selectedRecordIds == null || !selectedRecordIds.contains(record.getRecordId())) return false;
        } else if ("UNSELECTED".equalsIgnoreCase(selectionFilter)) {
            if (selectedRecordIds != null && selectedRecordIds.contains(record.getRecordId())) return false;
        }

        // 3. In-scope check
        if (inScopeOnly && !record.isInScope()) return false;

        // 4. Host & Subdomain checks
        if (!hostFilter.isEmpty()) {
            String h = record.getHost().toLowerCase(Locale.ROOT);
            if (!h.contains(hostFilter)) return false;
        }

        if (enabledDomains != null && !enabledDomains.isEmpty()) {
            String host = record.getHost().toLowerCase(Locale.ROOT);
            boolean domainMatch = false;
            for (String d : enabledDomains) {
                if (host.equals(d) || host.endsWith("." + d)) {
                    domainMatch = true;
                    break;
                }
            }
            if (!domainMatch) return false;
        }

        // 5. Enabled methods check
        if (enabledMethods != null && !enabledMethods.isEmpty()) {
            if (!enabledMethods.contains(record.getMethod().toUpperCase(Locale.ROOT))) {
                return false;
            }
        }

        // 6. Exclude static assets
        if (excludeStaticAssets) {
            String path = record.getPath().toLowerCase(Locale.ROOT);
            int q = path.indexOf('?');
            String cleanPath = q > 0 ? path.substring(0, q) : path;
            for (String ext : STATIC_EXTENSIONS) {
                if (cleanPath.endsWith(ext)) return false;
            }
        }

        // 7. Status Code check (Group, Category, or Custom Range)
        if (!matchesStatusCode(record.getStatusCode())) {
            return false;
        }

        // 8. MIME Type check
        if (!matchesMimeType(record.getContentType())) {
            return false;
        }

        // 9. Time Range check
        if (!matchesTimeRange(record.getRequestTimestamp())) {
            return false;
        }

        // 10. Authentication Endpoints filter
        if (authEndpointsOnly && !isAuthRelatedEndpoint(record)) {
            return false;
        }

        // 11. Specific API / Path filter
        if (!endpointPath.isEmpty()) {
            String path = record.getPath().toLowerCase(Locale.ROOT);
            if (!path.contains(endpointPath)) return false;
        }

        // 12. Advanced Traffic Search
        if (!advancedQuery.isEmpty()) {
            boolean matched = matchesAdvancedSearch(record);
            if (invertMatch ? matched : !matched) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesStatusCode(int code) {
        // Custom string check first (e.g. "200, 302, 401-404, 5xx")
        if (!statusCodeCustom.isEmpty()) {
            return checkCustomStatusRanges(code, statusCodeCustom);
        }

        if ("2xx".equalsIgnoreCase(statusCodeGroup) && (code < 200 || code >= 300)) return false;
        if ("3xx".equalsIgnoreCase(statusCodeGroup) && (code < 300 || code >= 400)) return false;
        if ("4xx".equalsIgnoreCase(statusCodeGroup) && (code < 400 || code >= 500)) return false;
        if ("5xx".equalsIgnoreCase(statusCodeGroup) && (code < 500 || code >= 600)) return false;
        if ("AUTH_ERRORS".equalsIgnoreCase(statusCodeGroup) && code != 401 && code != 403) return false;

        return true;
    }

    private boolean checkCustomStatusRanges(int code, String custom) {
        String[] parts = custom.split("[,; ]+");
        for (String p : parts) {
            p = p.trim().toLowerCase(Locale.ROOT);
            if (p.isEmpty()) continue;
            if (p.equals("2xx") && code >= 200 && code < 300) return true;
            if (p.equals("3xx") && code >= 300 && code < 400) return true;
            if (p.equals("4xx") && code >= 400 && code < 500) return true;
            if (p.equals("5xx") && code >= 500 && code < 600) return true;
            if (p.contains("-")) {
                String[] range = p.split("-");
                if (range.length == 2) {
                    try {
                        int rFrom = Integer.parseInt(range[0].trim());
                        int rTo = Integer.parseInt(range[1].trim());
                        if (code >= rFrom && code <= rTo) return true;
                    } catch (NumberFormatException ignored) {}
                }
            } else {
                try {
                    int exact = Integer.parseInt(p);
                    if (code == exact) return true;
                } catch (NumberFormatException ignored) {}
            }
        }
        return false;
    }

    private boolean matchesMimeType(String contentType) {
        if (!mimeCustom.isEmpty()) {
            if (contentType == null || !contentType.toLowerCase(Locale.ROOT).contains(mimeCustom)) {
                return false;
            }
        }

        if (mimeCategory == MimeCategory.ALL) return true;
        if (contentType == null) return false;
        String ct = contentType.toLowerCase(Locale.ROOT);

        switch (mimeCategory) {
            case JSON:
                return ct.contains("application/json") || ct.contains("+json");
            case HTML:
                return ct.contains("text/html");
            case XML:
                return ct.contains("text/xml") || ct.contains("application/xml") || ct.contains("+xml");
            case PLAIN_TEXT:
                return ct.contains("text/plain");
            case SCRIPT_CSS:
                return ct.contains("javascript") || ct.contains("text/css");
            case BINARY_MEDIA:
                return ct.contains("image/") || ct.contains("audio/") || ct.contains("video/")
                        || ct.contains("application/octet-stream") || ct.contains("application/pdf")
                        || ct.contains("application/zip") || ct.contains("application/gzip");
            default:
                return true;
        }
    }

    private boolean matchesTimeRange(long timestamp) {
        if (timeRangeMode == TimeRangeMode.ALL_TIME) return true;

        long now = System.currentTimeMillis();
        switch (timeRangeMode) {
            case LAST_5_MIN:
                return timestamp >= (now - 5 * 60 * 1000L);
            case LAST_15_MIN:
                return timestamp >= (now - 15 * 60 * 1000L);
            case LAST_1_HOUR:
                return timestamp >= (now - 60 * 60 * 1000L);
            case LAST_24_HOURS:
                return timestamp >= (now - 24 * 60 * 60 * 1000L);
            case CUSTOM:
                if (timeRangeFrom != null && timestamp < timeRangeFrom) return false;
                if (timeRangeTo != null && timestamp > timeRangeTo) return false;
                return true;
            default:
                return true;
        }
    }

    private boolean isAuthRelatedEndpoint(TrafficRecord record) {
        // Path check
        String path = record.getPath().toLowerCase(Locale.ROOT);
        for (String kw : AUTH_PATH_KEYWORDS) {
            if (path.contains(kw)) return true;
        }

        // Request Headers check
        for (String h : record.getRequestHeaders()) {
            String lower = h.toLowerCase(Locale.ROOT);
            if (lower.startsWith("authorization:") || lower.startsWith("x-api-key:") || lower.startsWith("apikey:")) {
                return true;
            }
            if (lower.startsWith("cookie:") && (lower.contains("session") || lower.contains("token") || lower.contains("auth"))) {
                return true;
            }
        }

        // Response Headers check
        for (String h : record.getResponseHeaders()) {
            String lower = h.toLowerCase(Locale.ROOT);
            if (lower.startsWith("set-cookie:") && (lower.contains("session") || lower.contains("token") || lower.contains("auth"))) {
                return true;
            }
            if (lower.startsWith("www-authenticate:")) {
                return true;
            }
        }

        return false;
    }

    private boolean matchesAdvancedSearch(TrafficRecord record) {
        switch (searchScope) {
            case URL:
                return evaluateTarget(record.getUrl());
            case HEADERS:
                return evaluateTarget(String.join("\n", record.getRequestHeaders()) + "\n" + String.join("\n", record.getResponseHeaders()));
            case REQ_BODY:
                return evaluateTarget(record.getRequestBodyAsString());
            case RESP_BODY:
                return evaluateTarget(record.getResponseBodyAsString());
            case PARAMS:
                return evaluateParameters(record);
            case STATUS:
                return evaluateTarget(record.getStatusCode() + " " + record.getStatusReason());
            case METHOD:
                return evaluateTarget(record.getMethod());
            case EVERYWHERE:
            default:
                return evaluateTarget(record.getUrl())
                        || evaluateTarget(record.getMethod())
                        || evaluateTarget(String.valueOf(record.getStatusCode()))
                        || evaluateTarget(String.join("\n", record.getRequestHeaders()))
                        || evaluateTarget(String.join("\n", record.getResponseHeaders()))
                        || evaluateTarget(record.getRequestBodyAsString())
                        || evaluateTarget(record.getResponseBodyAsString());
        }
    }

    private boolean evaluateParameters(TrafficRecord record) {
        // Query parameters
        String url = record.getUrl();
        int q = url.indexOf('?');
        if (q > 0 && evaluateTarget(url.substring(q + 1))) return true;

        // Form or JSON body parameters
        String reqBody = record.getRequestBodyAsString();
        return evaluateTarget(reqBody);
    }

    private boolean evaluateTarget(String targetText) {
        if (targetText == null) return false;

        if (regexMode && compiledPattern != null) {
            return compiledPattern.matcher(targetText).find();
        }

        if (caseSensitive) {
            return targetText.contains(advancedQuery);
        } else {
            return targetText.toLowerCase(Locale.ROOT).contains(advancedQuery.toLowerCase(Locale.ROOT));
        }
    }

    public List<TrafficRecord> filter(List<TrafficRecord> allRecords) {
        List<TrafficRecord> filtered = new ArrayList<>();
        if (allRecords == null) return filtered;
        for (TrafficRecord r : allRecords) {
            if (matches(r)) {
                filtered.add(r);
            }
        }
        return filtered;
    }
}
