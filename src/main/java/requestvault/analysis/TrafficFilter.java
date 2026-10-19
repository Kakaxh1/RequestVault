package requestvault.analysis;

import requestvault.model.TrafficRecord;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class TrafficFilter {

    private String searchKeyword;
    private String endpointPath;
    private String method;
    private String statusCodeGroup;
    private String statusCodeCustom;
    private String contentType;
    private Boolean inScopeOnly;
    private String selectionFilter; // "ALL", "SELECTED", "UNSELECTED"
    private Set<String> selectedRecordIds;
    private Integer rangeFrom;
    private Integer rangeTo;

    // Advanced filters matching the reference layout
    private Set<String> enabledDomains;
    private Set<String> enabledMethods;
    private boolean excludeStaticAssets;

    private static final Set<String> STATIC_EXTENSIONS = new HashSet<>(Arrays.asList(
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3"
    ));

    public TrafficFilter() {
        this.searchKeyword = "";
        this.endpointPath = "";
        this.method = "ALL";
        this.statusCodeGroup = "ALL";
        this.statusCodeCustom = "";
        this.contentType = "ALL";
        this.inScopeOnly = false;
        this.selectionFilter = "ALL";
        this.rangeFrom = null;
        this.rangeTo = null;
        this.enabledDomains = null;
        this.enabledMethods = null;
        this.excludeStaticAssets = false;
    }

    public void setSearchKeyword(String searchKeyword) {
        this.searchKeyword = searchKeyword != null ? searchKeyword.trim().toLowerCase(Locale.ROOT) : "";
    }

    public void setEndpointPath(String endpointPath) {
        this.endpointPath = endpointPath != null ? endpointPath.trim().toLowerCase(Locale.ROOT) : "";
    }

    public void setMethod(String method) {
        this.method = method != null ? method.trim().toUpperCase(Locale.ROOT) : "ALL";
    }

    public void setStatusCodeGroup(String statusCodeGroup) {
        this.statusCodeGroup = statusCodeGroup != null ? statusCodeGroup.trim() : "ALL";
    }

    public void setStatusCodeCustom(String statusCodeCustom) {
        this.statusCodeCustom = statusCodeCustom != null ? statusCodeCustom.trim() : "";
    }

    public void setContentType(String contentType) {
        this.contentType = contentType != null ? contentType.trim().toLowerCase(Locale.ROOT) : "ALL";
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

    public void setEnabledDomains(Set<String> enabledDomains) {
        this.enabledDomains = enabledDomains;
    }

    public void setEnabledMethods(Set<String> enabledMethods) {
        this.enabledMethods = enabledMethods;
    }

    public void setExcludeStaticAssets(boolean excludeStaticAssets) {
        this.excludeStaticAssets = excludeStaticAssets;
    }

    public boolean matches(TrafficRecord record) {
        if (record == null) return false;

        // Sequence number range check (#from to #to)
        if (rangeFrom != null && rangeFrom > 0) {
            if (record.getSequenceNumber() < rangeFrom) return false;
        }
        if (rangeTo != null && rangeTo > 0) {
            if (record.getSequenceNumber() > rangeTo) return false;
        }

        // Domain filter check
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

        // Enabled methods check
        if (enabledMethods != null && !enabledMethods.isEmpty()) {
            if (!enabledMethods.contains(record.getMethod().toUpperCase(Locale.ROOT))) {
                return false;
            }
        }

        // Exclude static assets
        if (excludeStaticAssets) {
            String path = record.getPath().toLowerCase(Locale.ROOT);
            int q = path.indexOf('?');
            String cleanPath = q > 0 ? path.substring(0, q) : path;
            for (String ext : STATIC_EXTENSIONS) {
                if (cleanPath.endsWith(ext)) {
                    return false;
                }
            }
        }

        // Selection filter check
        if ("SELECTED".equalsIgnoreCase(selectionFilter)) {
            if (selectedRecordIds == null || !selectedRecordIds.contains(record.getRecordId())) {
                return false;
            }
        } else if ("UNSELECTED".equalsIgnoreCase(selectionFilter)) {
            if (selectedRecordIds != null && selectedRecordIds.contains(record.getRecordId())) {
                return false;
            }
        }

        // In scope check
        if (inScopeOnly && !record.isInScope()) {
            return false;
        }

        // Method check
        if (!"ALL".equalsIgnoreCase(method) && !method.equalsIgnoreCase(record.getMethod())) {
            return false;
        }

        // Status code check (preset group or custom)
        if (!statusCodeCustom.isEmpty()) {
            String codeStr = String.valueOf(record.getStatusCode());
            if (!statusCodeCustom.contains(codeStr)) {
                // Check if e.g. "2xx" in custom
                boolean match = false;
                int code = record.getStatusCode();
                if (statusCodeCustom.contains("2xx") && code >= 200 && code < 300) match = true;
                if (statusCodeCustom.contains("3xx") && code >= 300 && code < 400) match = true;
                if (statusCodeCustom.contains("4xx") && code >= 400 && code < 500) match = true;
                if (statusCodeCustom.contains("5xx") && code >= 500 && code < 600) match = true;
                if (!match) return false;
            }
        } else if (!"ALL".equalsIgnoreCase(statusCodeGroup)) {
            int code = record.getStatusCode();
            if ("2xx".equalsIgnoreCase(statusCodeGroup) && (code < 200 || code >= 300)) return false;
            if ("3xx".equalsIgnoreCase(statusCodeGroup) && (code < 300 || code >= 400)) return false;
            if ("4xx".equalsIgnoreCase(statusCodeGroup) && (code < 400 || code >= 500)) return false;
            if ("5xx".equalsIgnoreCase(statusCodeGroup) && (code < 500 || code >= 600)) return false;
        }

        // Content type check
        if (!"ALL".equalsIgnoreCase(contentType) && !contentType.isEmpty()) {
            String ct = record.getContentType().toLowerCase(Locale.ROOT);
            if (!ct.contains(contentType)) return false;
        }

        // Specific API / Endpoint Path check
        if (!endpointPath.isEmpty()) {
            String path = record.getPath().toLowerCase(Locale.ROOT);
            if (!path.contains(endpointPath)) return false;
        }

        // Global search keyword check
        if (!searchKeyword.isEmpty()) {
            boolean found = record.getUrl().toLowerCase(Locale.ROOT).contains(searchKeyword)
                    || record.getHost().toLowerCase(Locale.ROOT).contains(searchKeyword)
                    || record.getPath().toLowerCase(Locale.ROOT).contains(searchKeyword)
                    || record.getRequestBodyAsString().toLowerCase(Locale.ROOT).contains(searchKeyword)
                    || record.getResponseBodyAsString().toLowerCase(Locale.ROOT).contains(searchKeyword);
            if (!found) return false;
        }

        return true;
    }

    public List<TrafficRecord> filter(List<TrafficRecord> allRecords) {
        List<TrafficRecord> filtered = new ArrayList<>();
        for (TrafficRecord r : allRecords) {
            if (matches(r)) {
                filtered.add(r);
            }
        }
        return filtered;
    }
}
