package requestvault.security;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RedactionEngine {

    private final Set<String> sensitiveHeaders = new HashSet<>(Arrays.asList(
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "api-key", "token", "x-auth-token", "x-access-token",
            "x-csrf-token", "session", "jwt"
    ));

    private final List<Pattern> jsonValuePatterns = Arrays.asList(
            Pattern.compile("\"(password|passwd|secret|token|access_token|refresh_token|api_?key|auth)\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"(password|passwd|secret|token|access_token|refresh_token|api_?key|auth)\"\\s*:\\s*([^,}\\]\\s]+)", Pattern.CASE_INSENSITIVE)
    );

    public boolean isSensitiveHeader(String headerName) {
        if (headerName == null) return false;
        return sensitiveHeaders.contains(headerName.trim().toLowerCase());
    }

    public List<String> redactHeaders(List<String> headers) {
        if (headers == null) return new ArrayList<>();
        List<String> redacted = new ArrayList<>();
        for (String h : headers) {
            int colon = h.indexOf(':');
            if (colon > 0) {
                String name = h.substring(0, colon).trim();
                String val = h.substring(colon + 1).trim();
                String nameLower = name.toLowerCase();

                if ("authorization".equals(nameLower) || "proxy-authorization".equals(nameLower)) {
                    if (val.toLowerCase().startsWith("bearer ")) {
                        redacted.add(name + ": Bearer <REDACTED>");
                    } else if (val.toLowerCase().startsWith("basic ")) {
                        redacted.add(name + ": Basic <REDACTED>");
                    } else {
                        redacted.add(name + ": <REDACTED>");
                    }
                    continue;
                } else if ("set-cookie".equals(nameLower)) {
                    // e.g. session=<REDACTED>; HttpOnly; Secure
                    int semi = val.indexOf(';');
                    String cookiePart = semi > 0 ? val.substring(0, semi) : val;
                    String rest = semi > 0 ? val.substring(semi) : "";
                    int eq = cookiePart.indexOf('=');
                    if (eq > 0) {
                        String cookieName = cookiePart.substring(0, eq).trim();
                        redacted.add(name + ": " + cookieName + "=<REDACTED>" + rest);
                    } else {
                        redacted.add(name + ": <REDACTED>" + rest);
                    }
                    continue;
                } else if ("cookie".equals(nameLower)) {
                    String[] parts = val.split(";");
                    List<String> redParts = new ArrayList<>();
                    for (String p : parts) {
                        int eq = p.indexOf('=');
                        if (eq > 0) {
                            redParts.add(p.substring(0, eq).trim() + "=<REDACTED>");
                        } else {
                            redParts.add("<REDACTED>");
                        }
                    }
                    redacted.add(name + ": " + String.join("; ", redParts));
                    continue;
                } else if (isSensitiveHeader(name)) {
                    redacted.add(name + ": <REDACTED>");
                    continue;
                }
            }
            redacted.add(h);
        }
        return redacted;
    }

    public String redactBody(String body) {
        if (body == null || body.isEmpty()) return body;

        String sanitized = body;
        for (Pattern pattern : jsonValuePatterns) {
            Matcher m = pattern.matcher(sanitized);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String fieldName = m.group(1);
                m.appendReplacement(sb, Matcher.quoteReplacement("\"" + fieldName + "\": \"<REDACTED>\""));
            }
            m.appendTail(sb);
            sanitized = sb.toString();
        }
        return sanitized;
    }

    public byte[] redactBytes(byte[] rawBytes, int bodyOffset, List<String> originalHeaders) {
        if (rawBytes == null) return null;
        List<String> sanitizedHeaders = redactHeaders(originalHeaders);
        
        StringBuilder sb = new StringBuilder();
        for (String h : sanitizedHeaders) {
            sb.append(h).append("\r\n");
        }
        sb.append("\r\n");
        byte[] headerBytes = sb.toString().getBytes(StandardCharsets.ISO_8859_1);

        byte[] bodyBytes = new byte[0];
        if (bodyOffset >= 0 && bodyOffset < rawBytes.length) {
            int bodyLen = rawBytes.length - bodyOffset;
            byte[] rawBody = new byte[bodyLen];
            System.arraycopy(rawBytes, bodyOffset, rawBody, 0, bodyLen);
            String bodyStr = new String(rawBody, StandardCharsets.UTF_8);
            String sanitizedBody = redactBody(bodyStr);
            bodyBytes = sanitizedBody.getBytes(StandardCharsets.UTF_8);
        }

        byte[] result = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, result, headerBytes.length, bodyBytes.length);
        return result;
    }
}
