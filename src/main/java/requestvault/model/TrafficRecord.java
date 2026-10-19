package requestvault.model;

import requestvault.security.HashService;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class TrafficRecord {

    private final String recordId;
    private String engagementId;
    private final byte[] requestBytes;
    private final byte[] responseBytes;

    private final String protocol;
    private final String host;
    private final int port;
    private final String method;
    private final String path;
    private final String url;

    private final List<String> requestHeaders;
    private final int requestBodyOffset;
    private final String requestHash;

    private final int statusCode;
    private final String statusReason;
    private final List<String> responseHeaders;
    private final int responseBodyOffset;
    private final String responseHash;
    private final String contentType;

    private final long requestTimestamp;
    private final long responseTimestamp;
    private final long durationMs;
    private final String sourceTool;
    private boolean inScope;
    private int sequenceNumber;

    public TrafficRecord(
            String recordId,
            String engagementId,
            byte[] requestBytes,
            byte[] responseBytes,
            String protocol,
            String host,
            int port,
            String method,
            String path,
            String url,
            List<String> requestHeaders,
            int requestBodyOffset,
            int statusCode,
            String statusReason,
            List<String> responseHeaders,
            int responseBodyOffset,
            String contentType,
            long requestTimestamp,
            long responseTimestamp,
            long durationMs,
            String sourceTool,
            boolean inScope) {

        this.recordId = (recordId != null && !recordId.isEmpty()) ? recordId : UUID.randomUUID().toString();
        this.engagementId = engagementId;
        this.requestBytes = requestBytes != null ? requestBytes : new byte[0];
        this.responseBytes = responseBytes; // can be null if pending/no response
        
        this.protocol = protocol != null ? protocol : "http";
        this.host = host != null ? host : "";
        this.port = port;
        this.method = method != null ? method : "GET";
        this.path = path != null ? path : "/";
        this.url = url != null ? url : (this.protocol + "://" + this.host + (this.port != 80 && this.port != 443 ? ":" + this.port : "") + this.path);

        this.requestHeaders = requestHeaders != null ? new ArrayList<>(requestHeaders) : new ArrayList<>();
        this.requestBodyOffset = requestBodyOffset;
        this.requestHash = HashService.sha256(this.requestBytes);

        this.statusCode = statusCode;
        this.statusReason = statusReason != null ? statusReason : "";
        this.responseHeaders = responseHeaders != null ? new ArrayList<>(responseHeaders) : new ArrayList<>();
        this.responseBodyOffset = responseBodyOffset;
        this.responseHash = responseBytes != null ? HashService.sha256(this.responseBytes) : null;
        this.contentType = contentType != null ? contentType : "";

        this.requestTimestamp = requestTimestamp;
        this.responseTimestamp = responseTimestamp;
        this.durationMs = durationMs;
        this.sourceTool = sourceTool != null ? sourceTool : "Proxy";
        this.inScope = inScope;
    }

    public String getRecordId() { return recordId; }
    public String getEngagementId() { return engagementId; }
    public void setEngagementId(String engagementId) { this.engagementId = engagementId; }

    public byte[] getRequestBytes() { return requestBytes; }
    public byte[] getResponseBytes() { return responseBytes; }
    public boolean hasResponse() { return responseBytes != null && responseBytes.length > 0; }

    public String getProtocol() { return protocol; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getUrl() { return url; }

    public List<String> getRequestHeaders() { return requestHeaders; }
    public int getRequestBodyOffset() { return requestBodyOffset; }
    public String getRequestHash() { return requestHash; }

    public int getStatusCode() { return statusCode; }
    public String getStatusReason() { return statusReason; }
    public List<String> getResponseHeaders() { return responseHeaders; }
    public int getResponseBodyOffset() { return responseBodyOffset; }
    public String getResponseHash() { return responseHash; }
    public String getContentType() { return contentType; }

    public long getRequestTimestamp() { return requestTimestamp; }
    public long getResponseTimestamp() { return responseTimestamp; }
    public long getDurationMs() { return durationMs; }
    public String getSourceTool() { return sourceTool; }
    public boolean isInScope() { return inScope; }
    public void setInScope(boolean inScope) { this.inScope = inScope; }

    public String getRequestBodyAsString() {
        if (requestBytes == null || requestBodyOffset < 0 || requestBodyOffset >= requestBytes.length) {
            return "";
        }
        int len = requestBytes.length - requestBodyOffset;
        return new String(requestBytes, requestBodyOffset, len, StandardCharsets.UTF_8);
    }

    public String getResponseBodyAsString() {
        if (responseBytes == null || responseBodyOffset < 0 || responseBodyOffset >= responseBytes.length) {
            return "";
        }
        int len = responseBytes.length - responseBodyOffset;
        return new String(responseBytes, responseBodyOffset, len, StandardCharsets.UTF_8);
    }

    public byte[] getResponseBodyBytes() {
        if (responseBytes == null || responseBodyOffset < 0 || responseBodyOffset >= responseBytes.length) {
            return new byte[0];
        }
        int len = responseBytes.length - responseBodyOffset;
        byte[] body = new byte[len];
        System.arraycopy(responseBytes, responseBodyOffset, body, 0, len);
        return body;
    }

    public int getRequestSize() {
        return requestBytes != null ? requestBytes.length : 0;
    }

    public int getResponseSize() {
        return responseBytes != null ? responseBytes.length : 0;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }
}
