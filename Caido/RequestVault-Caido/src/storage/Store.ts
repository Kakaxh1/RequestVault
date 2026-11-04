/**
 * RequestVault for Caido - Traffic Store & Filtering Engine
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

import { FilterState, TrafficRecord } from "../types";

export type StoreListener = () => void;

export class TrafficStore {
  private records: TrafficRecord[] = [];
  private recordsById: Map<string, TrafficRecord> = new Map();
  private seenHashes: Set<string> = new Set();
  private sequenceCounter = 1;
  private listeners: StoreListener[] = [];

  public getAll(): TrafficRecord[] {
    return this.records;
  }

  public getById(id: string): TrafficRecord | undefined {
    return this.recordsById.get(id);
  }

  public addRecord(record: TrafficRecord, deduplicate = true): boolean {
    const dedupeKey = `${record.method}:${record.url}:${record.requestHash || record.requestBody}`;
    if (deduplicate && this.seenHashes.has(dedupeKey)) {
      return false;
    }

    record.sequenceNumber = this.sequenceCounter++;
    this.seenHashes.add(dedupeKey);
    this.records.push(record);
    this.recordsById.set(record.recordId, record);
    this.notify();
    return true;
  }

  public addRecords(records: TrafficRecord[], deduplicate = true): number {
    let added = 0;
    for (const r of records) {
      if (this.addRecord(r, deduplicate)) {
        added++;
      }
    }
    return added;
  }

  public clear(): void {
    this.records = [];
    this.recordsById.clear();
    this.seenHashes.clear();
    this.sequenceCounter = 1;
    this.notify();
  }

  public subscribe(fn: StoreListener): () => void {
    this.listeners.push(fn);
    return () => {
      this.listeners = this.listeners.filter(l => l !== fn);
    };
  }

  private notify(): void {
    for (const l of this.listeners) {
      try { l(); } catch (err) { console.error("RequestVault store listener error:", err); }
    }
  }

  // -------------------------------------------------------------
  // Domain Hierarchy Extractor
  // -------------------------------------------------------------
  public getDomainHierarchy(): Map<string, Set<string>> {
    const hierarchy = new Map<string, Set<string>>();
    for (const r of this.records) {
      if (!r.host) continue;
      const host = r.host.toLowerCase();
      const apex = this.getApexDomain(host);

      if (!hierarchy.has(apex)) {
        hierarchy.set(apex, new Set<string>());
      }
      hierarchy.get(apex)!.add(host);
    }
    return hierarchy;
  }

  public getApexDomain(host: string): string {
    if (!host) return "unknown";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host; // IPv4
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    // Basic multi-part TLD heuristic (e.g. co.uk, com.au)
    const secondLast = parts[parts.length - 2];
    if (secondLast.length <= 3 && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  // -------------------------------------------------------------
  // Filter Engine
  // -------------------------------------------------------------
  public filterRecords(state: FilterState, selectedIds: Set<string>): TrafficRecord[] {
    const now = Date.now();

    return this.records.filter(r => {
      // 1. Selected Only Filter
      if (state.selectedOnly && !selectedIds.has(r.recordId)) {
        return false;
      }

      // 2. Domain Filter
      if (state.selectedDomains.size > 0 && r.host) {
        if (!state.selectedDomains.has(r.host.toLowerCase())) {
          return false;
        }
      }

      // 3. Time Range Filter
      if (state.timeRange !== "ALL_TIME") {
        const delta = now - r.timestamp;
        if (state.timeRange === "LAST_5_MIN" && delta > 5 * 60 * 1000) return false;
        if (state.timeRange === "LAST_15_MIN" && delta > 15 * 60 * 1000) return false;
        if (state.timeRange === "LAST_1_HOUR" && delta > 60 * 60 * 1000) return false;
        if (state.timeRange === "LAST_24_HOURS" && delta > 24 * 60 * 60 * 1000) return false;
      }

      // 4. Status Filter
      if (state.statusCategory !== "ALL") {
        const sc = r.statusCode;
        if (state.statusCategory === "2XX" && (sc < 200 || sc >= 300)) return false;
        if (state.statusCategory === "3XX" && (sc < 300 || sc >= 400)) return false;
        if (state.statusCategory === "4XX" && (sc < 400 || sc >= 500)) return false;
        if (state.statusCategory === "5XX" && (sc < 500 || sc >= 600)) return false;
        if (state.statusCategory === "AUTH_FAILURES" && sc !== 401 && sc !== 403) return false;
        if (state.statusCategory === "CUSTOM" && state.customStatusRange) {
          if (!this.matchesStatusRange(sc, state.customStatusRange)) return false;
        }
      }

      // 5. MIME Category Filter
      if (state.mimeCategory !== "ALL") {
        const ct = (r.contentType || "").toLowerCase();
        if (state.mimeCategory === "JSON" && !ct.includes("json")) return false;
        if (state.mimeCategory === "HTML" && !ct.includes("html")) return false;
        if (state.mimeCategory === "XML" && !ct.includes("xml")) return false;
        if (state.mimeCategory === "PLAIN_TEXT" && !ct.includes("text/plain")) return false;
        if (state.mimeCategory === "SCRIPTS" && !ct.includes("javascript") && !ct.includes("css")) return false;
        if (state.mimeCategory === "BINARY_MEDIA" && !ct.includes("image") && !ct.includes("octet-stream") && !ct.includes("pdf")) return false;
      }

      // 6. API Path Filter
      if (state.apiPath && state.apiPath.trim()) {
        const p = state.apiPath.trim().toLowerCase();
        if (!r.path.toLowerCase().includes(p)) return false;
      }

      // 7. Auth Endpoints Only
      if (state.authEndpointsOnly) {
        if (!this.isAuthSurface(r)) return false;
      }

      // 8. Search Term (Full-text / Regex / Scoped)
      if (state.searchTerm && state.searchTerm.trim()) {
        const term = state.searchTerm.trim();
        const matched = this.matchSearch(r, term, state.searchScope, state.searchRegex, state.searchCaseSensitive);
        if (state.searchInvert) {
          if (matched) return false;
        } else {
          if (!matched) return false;
        }
      }

      return true;
    });
  }

  private isAuthSurface(r: TrafficRecord): boolean {
    const p = (r.path || "").toLowerCase();
    const keywords = ["/login", "/auth", "/token", "/oauth", "/session", "/jwt", "/saml", "/register", "/signin", "/sso", "/mfa"];
    if (keywords.some(k => p.includes(k))) return true;

    // Check request headers
    if (r.requestHeaders) {
      for (const h of r.requestHeaders) {
        const lower = h.toLowerCase();
        if (lower.startsWith("authorization:") || lower.startsWith("x-api-key:") || lower.startsWith("bearer ") || lower.startsWith("cookie:")) {
          return true;
        }
      }
    }
    return false;
  }

  private matchesStatusRange(code: number, spec: string): boolean {
    if (!spec || !code) return false;
    const tokens = spec.split(",").map(t => t.trim());
    for (const t of tokens) {
      if (t.endsWith("xx") || t.endsWith("XX")) {
        const lead = parseInt(t[0], 10);
        if (!isNaN(lead) && Math.floor(code / 100) === lead) return true;
      } else if (t.includes("-")) {
        const [lowStr, highStr] = t.split("-").map(x => x.trim());
        const low = parseInt(lowStr, 10);
        const high = parseInt(highStr, 10);
        if (!isNaN(low) && !isNaN(high) && code >= low && code <= high) return true;
      } else {
        const exact = parseInt(t, 10);
        if (!isNaN(exact) && code === exact) return true;
      }
    }
    return false;
  }

  private matchSearch(
    r: TrafficRecord,
    query: string,
    scope: FilterState["searchScope"],
    regex: boolean,
    caseSensitive: boolean
  ): boolean {
    let target = "";
    switch (scope) {
      case "URL_PATH":
        target = r.url || "";
        break;
      case "HEADERS":
        target = `${(r.requestHeaders || []).join("\n")}\n${(r.responseHeaders || []).join("\n")}`;
        break;
      case "REQ_BODY":
        target = r.requestBody || "";
        break;
      case "RESP_BODY":
        target = r.responseBody || "";
        break;
      case "METHOD":
        target = r.method || "";
        break;
      case "STATUS":
        target = String(r.statusCode || "");
        break;
      case "EVERYWHERE":
      default:
        target = `${r.method} ${r.url} ${(r.requestHeaders || []).join(" ")} ${r.requestBody} ${r.statusCode} ${(r.responseHeaders || []).join(" ")} ${r.responseBody}`;
        break;
    }

    if (regex) {
      try {
        const re = new RegExp(query, caseSensitive ? "" : "i");
        return re.test(target);
      } catch {
        return false;
      }
    }

    if (!caseSensitive) {
      return target.toLowerCase().includes(query.toLowerCase());
    }
    return target.includes(query);
  }
}
