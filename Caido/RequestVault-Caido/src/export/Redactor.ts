/**
 * RequestVault for Caido - Non-Destructive Secret Redaction Engine
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { TrafficRecord } from "../types";

export class Redactor {
  private static readonly REDACTED_MASK = "<REDACTED>";

  public static redactRecord(record: TrafficRecord): TrafficRecord {
    const copy: TrafficRecord = { ...record };

    // 1. Redact Request Headers
    if (copy.requestHeaders && copy.requestHeaders.length > 0) {
      copy.requestHeaders = copy.requestHeaders.map(h => this.redactHeader(h));
    }

    // 2. Redact Response Headers
    if (copy.responseHeaders && copy.responseHeaders.length > 0) {
      copy.responseHeaders = copy.responseHeaders.map(h => this.redactHeader(h));
    }

    // 3. Redact Request Body
    if (copy.requestBody) {
      copy.requestBody = this.redactBody(copy.requestBody);
    }

    // 4. Redact Response Body
    if (copy.responseBody) {
      copy.responseBody = this.redactBody(copy.responseBody);
    }

    return copy;
  }

  private static redactHeader(header: string): string {
    if (!header) return "";
    const lower = header.toLowerCase();

    // Authorization: Bearer / Basic
    if (lower.startsWith("authorization:")) {
      if (lower.includes("bearer ")) {
        return "Authorization: Bearer " + this.REDACTED_MASK;
      } else if (lower.includes("basic ")) {
        return "Authorization: Basic " + this.REDACTED_MASK;
      }
      return "Authorization: " + this.REDACTED_MASK;
    }

    // Proxy-Authorization
    if (lower.startsWith("proxy-authorization:")) {
      return "Proxy-Authorization: " + this.REDACTED_MASK;
    }

    // Cookies
    if (lower.startsWith("cookie:")) {
      return this.redactCookieHeader(header, "Cookie: ");
    }
    if (lower.startsWith("set-cookie:")) {
      return this.redactCookieHeader(header, "Set-Cookie: ");
    }

    // Custom API Keys
    if (lower.startsWith("x-api-key:") || lower.startsWith("apikey:") || lower.startsWith("x-token:") || lower.startsWith("secret:")) {
      const colon = header.indexOf(":");
      return header.substring(0, colon + 1) + " " + this.REDACTED_MASK;
    }

    return header;
  }

  private static redactCookieHeader(header: string, prefix: string): string {
    const rawVal = header.substring(prefix.length);
    const parts = rawVal.split(";");
    const sanitizedParts: string[] = [];

    const sensitiveNames = ["token", "session", "jwt", "phpsessid", "jsessionid", "auth", "secret", "refresh_token", "access_token"];

    for (let part of parts) {
      const eq = part.indexOf("=");
      if (eq > 0) {
        const k = part.substring(0, eq).trim();
        if (sensitiveNames.some(s => k.toLowerCase().includes(s))) {
          sanitizedParts.push(`${k}=${this.REDACTED_MASK}`);
          continue;
        }
      }
      sanitizedParts.push(part);
    }

    return prefix + sanitizedParts.join("; ");
  }

  private static redactBody(body: string): string {
    if (!body) return "";

    // JSON token/password mask
    let result = body.replace(
      /("(?:password|token|access_token|refresh_token|secret|api_key|apiKey|client_secret)"\s*:\s*")([^"]+)(")/gi,
      `$1${this.REDACTED_MASK}$3`
    );

    // Form-urlencoded password mask
    result = result.replace(
      /((?:^|&)(?:password|passwd|token|secret|api_key)=)([^&]*)/gi,
      `$1${this.REDACTED_MASK}`
    );

    return result;
  }
}

