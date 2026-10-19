package requestvault.capture;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import requestvault.model.TrafficRecord;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class TrafficCapture {

    public static TrafficRecord fromMontoya(HttpRequestResponse message, String sourceTool, boolean inScope) {
        if (message == null) return null;
        long now = System.currentTimeMillis();
        return buildRecord(
                message.request(),
                message.hasResponse() ? message.response() : null,
                message.httpService(),
                now,
                0,
                sourceTool != null ? sourceTool : "Burp",
                inScope
        );
    }

    public static TrafficRecord fromProxyMessage(ProxyHttpRequestResponse message, boolean inScope) {
        if (message == null) return null;
        HttpRequest req = message.finalRequest() != null ? message.finalRequest() : message.request();
        HttpResponse resp = message.hasResponse() ? message.response() : null;
        HttpService service = message.httpService();

        long ts = System.currentTimeMillis();
        try {
            ZonedDateTime zdt = message.time();
            if (zdt != null) {
                ts = zdt.toInstant().toEpochMilli();
            }
        } catch (Exception ignored) {}

        long duration = 0;
        try {
            if (message.timingData() != null && message.timingData().timeBetweenRequestSentAndEndOfResponse() != null) {
                duration = message.timingData().timeBetweenRequestSentAndEndOfResponse().toMillis();
            }
        } catch (Exception ignored) {}

        return buildRecord(req, resp, service, ts, duration, "Proxy History", inScope);
    }

    public static TrafficRecord fromInterceptedResponse(InterceptedResponse interceptedResponse, boolean inScope) {
        if (interceptedResponse == null) return null;
        HttpRequest req = interceptedResponse.initiatingRequest() != null ? interceptedResponse.initiatingRequest() : interceptedResponse.request();
        HttpService service = req != null ? req.httpService() : null;

        long now = System.currentTimeMillis();
        return buildRecord(req, interceptedResponse, service, now, 0, "Proxy Live", inScope);
    }

    private static TrafficRecord buildRecord(HttpRequest req, HttpResponse resp, HttpService service,
                                             long timestamp, long durationMs, String sourceTool, boolean inScope) {
        String protocol = (service != null && service.secure()) ? "https" : "http";
        String host = service != null ? service.host() : "";
        int port = service != null ? service.port() : (protocol.equals("https") ? 443 : 80);

        String method = "GET";
        String path = "/";
        String url = "";
        byte[] reqBytes = new byte[0];
        List<String> reqHeaders = new ArrayList<>();
        int reqBodyOffset = 0;

        if (req != null) {
            method = req.method();
            path = req.path();
            url = req.url();
            if (host.isEmpty() && req.httpService() != null) {
                host = req.httpService().host();
                port = req.httpService().port();
                protocol = req.httpService().secure() ? "https" : "http";
            }
            ByteArray reqByteArr = req.toByteArray();
            reqBytes = reqByteArr != null ? reqByteArr.getBytes() : new byte[0];
            reqBodyOffset = req.bodyOffset();

            for (HttpHeader h : req.headers()) {
                reqHeaders.add(h.name() + ": " + h.value());
            }
        }

        int statusCode = 0;
        String statusReason = "";
        byte[] respBytes = null;
        List<String> respHeaders = new ArrayList<>();
        int respBodyOffset = 0;
        String contentType = "";

        if (resp != null) {
            statusCode = resp.statusCode();
            statusReason = resp.reasonPhrase();
            ByteArray respByteArr = resp.toByteArray();
            respBytes = respByteArr != null ? respByteArr.getBytes() : new byte[0];
            respBodyOffset = resp.bodyOffset();

            for (HttpHeader h : resp.headers()) {
                respHeaders.add(h.name() + ": " + h.value());
                if ("content-type".equalsIgnoreCase(h.name())) {
                    contentType = h.value();
                }
            }
        }

        return new TrafficRecord(
                UUID.randomUUID().toString(),
                null,
                reqBytes,
                respBytes,
                protocol,
                host,
                port,
                method,
                path,
                url,
                reqHeaders,
                reqBodyOffset,
                statusCode,
                statusReason,
                respHeaders,
                respBodyOffset,
                contentType,
                timestamp,
                timestamp + durationMs,
                durationMs,
                sourceTool,
                inScope
        );
    }
}
